var pageinfodict={};

function listener(details) {
	var pageanalysis=null;
	var iconcolor=0;
	var filter=browser.webRequest.filterResponseData(details.requestId);
	var decoder=new TextDecoder("utf-8");
	var encoder=new TextEncoder();
	var source='';
	filter.ondata = (event) => {
		let sub = decoder.decode(event.data, { stream: true });
		filter.write(encoder.encode(sub));
		source+=sub;
	};

	filter.onstop = (event) => {
		analyzepagesource(details.tabId, details.url, source)
		.then(function(result){	
			console.log('called analyzepagesource().  result:');	
			console.log(result);
			pageanalysis=result;
			pageinfodict[details.tabId]=pageanalysis;
			return browser.storage.local.get();
		}).then(function(result) {
			var truststore=result;

			if('hashes' in truststore) {
				for(var j=0; j<truststore.hashes.length; j++) {
					if(truststore.hashes[j]==pageanalysis.sha256hash) { iconcolor=2; }
				}
			}

			for(var i=0; i<pageanalysis.verifiedsignaturepublickeys.length; i++) {
				if(iconcolor==0) { iconcolor=1; }
				if('publickeys' in truststore) {
					for(var j=0; j<truststore.publickeys.length; j++) {
						if(truststore.publickeys[j].keydata==pageanalysis.verifiedsignaturepublickeys[i].keydata) { iconcolor=2; }
					}
				}
			}

			if(iconcolor==1) {
				browser.browserAction.setIcon( {path: {16: "icons/pi-yellow-16x16.png", 32: "icons/pi-yellow-32x32.png"}, tabId: pageanalysis['tabid'] });
			} else if(iconcolor==2) {
				browser.browserAction.setIcon( {path: {16: "icons/pi-green-16x16.png", 32: "icons/pi-green-32x32.png"}, tabId: pageanalysis['tabid'] });
			} else {
				browser.browserAction.setIcon( {path: {16: "icons/pi-white-16x16.png", 32: "icons/pi-white-32x32.png"}, tabId: pageanalysis['tabid'] });
			}
		});
		filter.disconnect();
	};

	return;
}

browser.webRequest.onBeforeRequest.addListener(
	listener,
	{ urls: ["https://*/*"], types: ["main_frame"] },
	["blocking"]
);

function getActiveTabInfo() {
	return new Promise((resolve, reject) => {
		browser.tabs.query({ currentWindow: true, active: true }).then((tabs) => {
			resolve(pageinfodict[tabs[0].id]);
		}, reject);
	});
}

async function analyzepagesource(tabid, url, source) {	
	console.log('////////// begin analyzepagesource() //////////')
	console.log(Date().toLocaleString());
	console.log('url: ' + url);

	var sourcebytes=new TextEncoder('utf-8').encode(source);
	var sha256hex=null;
	var verifiedsignaturepublickeys=[];

	//take sha256 hash of source
	var sha256=await window.crypto.subtle.digest("SHA-256", sourcebytes);
	var sha256=new Uint8Array(sha256);
	sha256hex=Uint8ArrayToHexString(sha256);
	console.log('sha256(source): ' + sha256hex);

	//look for pagesignatures metatag in source, and get pagesignatureurl if specified
	var pagesignaturesurl=null;
	var parser=new DOMParser();
	var doc=parser.parseFromString(source, 'text/html');
	var metatags=doc.getElementsByTagName('meta');
	for(var i=0; i<metatags.length; i++) {
		if(metatags[i].getAttribute('name')=='pagesignatures') { pagesignaturesurl=metatags[i].getAttribute('content'); }
	}
	console.log('pagesignaturesurl: ' + pagesignaturesurl);

	//use xhr to fetch json from pagesignaturesurl
	var xhrresponse=null;
	if(pagesignaturesurl) {	
		try {
			xhrresponse=await xhrrequest('GET', pagesignaturesurl);
		} catch(error) {
			console.log('unable to make xhr get request to pagesignaturesurl');
			console.log(error);
		}
	}

	//parse json
	if(xhrresponse && xhrresponse.target && xhrresponse.target.status && xhrresponse.target.status==200) {
		try {
			var pagesignaturesjson=xhrresponse.target.response;
			var pagesignatures=JSON.parse(pagesignaturesjson);
		} catch(error) {
			console.log('unable to parse json returned from pagesignaturesurl');
			console.log(error);
		}
	} else {
		console.log('invalid response to xhr get request to pagesignaturesurl');
	}

	//validate signatures in pagesignaturesurl
	if(pagesignatures && pagesignatures.signatures) {
		for(var i=0; i<pagesignatures.signatures.length; i++) {			
			console.log('----------')
			console.log('signature ' + i);	

			try {
				var publickeyalgorithm=pagesignatures.signatures[i].publickey.algorithm;
				var publickeybase64=pagesignatures.signatures[i].publickey.keydata;
				var publickeybytes=Base64StringToUint8Array(publickeybase64);
			} catch(err) {
				console.log('error parsing public key from json');
				console.error(err);
				continue;
			}

			try {
				var signaturealgorithm=pagesignatures.signatures[i].signature.algorithm;
				var signaturebase64=pagesignatures.signatures[i].signature.signature;
				var signaturebytes=Base64StringToUint8Array(signaturebase64);
			} catch(err) {
				console.log('error parsing signature from json');
				console.error(err);
				continue;
			}

			var publickey=await window.crypto.subtle.importKey('spki', publickeybytes, publickeyalgorithm, true, ["verify"])
			.catch(function(err) {
				console.log('error importing public key');
				console.error(err);
			});
			if(!publickey) { continue; }
			console.log('key imported');

			var signatureverification=await window.crypto.subtle.verify(signaturealgorithm, publickey, signaturebytes, sourcebytes)
			.catch(function(err) {
				console.log('error verifying signature');
				console.error(err);
			});
			if(signatureverification==null) { continue; }
			console.log('signature verified');

			console.log('publickeyalgorithm: ' + JSON.stringify(publickeyalgorithm));
			console.log('publickeybase64: ' + publickeybase64);
			console.log('signaturealgorithm: ' + JSON.stringify(signaturealgorithm));	
			console.log('signaturebase64: ' + signaturebase64);
			console.log('signatureverification: ' + signatureverification);
			console.log('----------')
			
			if(signatureverification) {			
				verifiedsignaturepublickeys.push(pagesignatures.signatures[i].publickey);
			}
		}	
	}

	console.log('////////// end analyzepagesource() //////////')

	var returndata={'tabid': tabid, 'url': url, 'pagesignaturesurl': pagesignaturesurl, 'sha256hash': sha256hex, 'verifiedsignaturepublickeys': verifiedsignaturepublickeys };
	return returndata;
}

function xhrrequest(method, url) {
	return new Promise(function (resolve, reject) {
		var xhr = new XMLHttpRequest();
		xhr.open(method, url);
		xhr.onload = resolve;
		xhr.onerror = reject;
		xhr.send();
	});
}



function Base64StringToUint8Array(base64string) {
	try {
		var binary=window.atob(base64string);
		var result=new Uint8Array(binary.length);
		for(var i=0; i<binary.length; i++)        {
			result[i]=binary.charCodeAt(i);
		}
		return result;
	} catch(error) {
		return null;
	}
}

function Uint8ArrayToHexString(ui8array) {
	try {
		var hexstring='', h;
		for(var i=0; i<ui8array.length; i++) {
			h=ui8array[i].toString(16);
			if(h.length==1) { h='0'+h; }
			hexstring+=h;
		}	

		//pad hex string with leading zeroes to make its length 2^n.
		var p=Math.pow(2, Math.ceil(Math.log2(hexstring.length)));
		hexstring=hexstring.padStart(p, '0');

		return hexstring;
	} catch(error) {
		return null;
	}
}



