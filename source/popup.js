var pageanalysis=null;
var getting = browser.runtime.getBackgroundPage();
getting.then(onGot, onError);

function onGot(page) {
	page.getActiveTabInfo()
	.then(function(result) {	
		pageanalysis=result;
		showpageanalysis();
	});
}

function onError(error) {
	console.log(`Error: ${error}`);
}


document.getElementById('atruststore').addEventListener('click', function() {		
	showtruststore();
});

document.getElementById('acopy').addEventListener('click', function() {		
		navigator.clipboard.writeText(document.getElementById("divmain").innerText).then(function() {
			alert('integrity information copied to clipboard.');
	}, function() {
		// clipboard write failed 
	});
});

document.getElementById('aabout').addEventListener('click', function() {	
	divhead.style.display='none';	
	document.getElementById('divmain').innerHTML='';
	document.getElementById('divmain').style="text-align: center;";

	var elem=document.createElement('p');
	elem.innerHTML='<big>Page Integrity</big>';
	elem.style="padding: 20px 0 0 0; text-align: center;";
	document.getElementById('divmain').appendChild(elem);

	var elem=document.createElement('p');
	elem.innerText='Version ' + browser.runtime.getManifest().version;
	elem.style="padding: 0 0 20px 0; text-align: center;";
	document.getElementById('divmain').appendChild(elem);


	var elem=document.createElement('a');
	elem.href="https://www.pageintegrity.net/";
	elem.innerText='https://www.pageintegrity.net/'; 
	elem.style="padding: 0 20px 0 20px; text-align: center;";
	document.getElementById('divmain').appendChild(elem);

	var elem=document.createElement('p');
	elem.style="padding: 10px 0 10px 0; text-align: center;";
	document.getElementById('divmain').appendChild(elem);

	var elem=document.createElement('a');
	elem.innerText='close'; 
	elem.style="text-align: center;";
	elem.addEventListener('click', function() {
		showpageanalysis();
	});
	document.getElementById('divmain').appendChild(elem);

	var elem=document.createElement('p');
	elem.style="padding: 10px 0 10px 0; text-align: center;";
	document.getElementById('divmain').appendChild(elem);

});


document.getElementById('acleartruststore').addEventListener('click', function() {		
	var r=confirm("Are you sure you want to clear the trust store?  This will remove all hashes and public keys from the trust store, and this action cannot be undone.");
	if(r==true) {
 		browser.storage.local.clear()
		.then(function(result){	
			showpageanalysis();
		});
	}
});

document.getElementById('aclosetruststore').addEventListener('click', function() {	
	divmainlinks.style.display='block';
	divtruststorelinks.style.display='none';
	showpageanalysis();
});

function wraplongstring(str) {
	return str.replace(/(.{64})/g, '$1\n');
}

function shortenlongstring(str) {
	var maxlength=64
	if(str.length>maxlength) {
		return(str.substr(0,32) + '...' + str.substr(-32));
	}  else {
		return(str);
	}
}

function addkeytotruststore(key) {
	browser.storage.local.get()
	.then(function(result) {	
		var truststore=result;
		if(!('publickeys' in truststore)) { truststore.publickeys=[]; }
		truststore.publickeys.push(key);
		return browser.storage.local.set(truststore);
	}).then(function(result) {
		 showpageanalysis();
	});
}

function removekeyfromtruststore(key) {
	browser.storage.local.get()
	.then(function(result) {	
		var truststore=result;
		if(!('publickeys' in truststore)) { truststore.publickeys=[]; }
		var i=0;
		while(i<truststore.publickeys.length) {
			if(truststore.publickeys[i].keydata==key) { truststore.publickeys.splice(i,1); }
			i++;
		}
		return browser.storage.local.set(truststore);
	}).then(function(result) {
		 showpageanalysis();
	});
}

function addhashtotruststore(hash) {
	browser.storage.local.get()
	.then(function(result) {	
		var truststore=result;
		if(!('hashes' in truststore)) { truststore.hashes=[]; }
		truststore.hashes.push(hash);
		return browser.storage.local.set(truststore);
	}).then(function(result) {
		 showpageanalysis();
	});
}

function removehashfromtruststore(hash) {
	browser.storage.local.get()
	.then(function(result) {	
		var truststore=result;
		if(!('hashes' in truststore)) { truststore.hashes=[]; }
		var i=0;
		while(i<truststore.hashes.length) {
			if(truststore.hashes[i]==hash) { truststore.hashes.splice(i,1); }
			i++;
		}
		return browser.storage.local.set(truststore);
	}).then(function(result) {
		 showpageanalysis();
	});
}

function showpageanalysis() {
	var iconcolor=0;
	divhead.style.display='block';	
	divmainlinks.style.display='block';
	divtruststorelinks.style.display='none';

	console.log('---pageanalysis---')
	console.log(pageanalysis);

	browser.storage.local.get()
	.then(function(result) {	
		var truststore=result;
		console.log('truststore');
		console.log(truststore);

		document.getElementById('divmain').style="text-align: left;";
		document.getElementById('divmain').innerHTML='';
		if(!pageanalysis) { 
			var elem=document.createElement('h6');
			elem.innerHTML='Reload page for integrity information.';
			document.getElementById('divmain').appendChild(elem);
		} else {
			var elem=document.createElement('h4');
			elem.innerText=shortenlongstring(pageanalysis['url']);
			document.getElementById('divmain').appendChild(elem);

			var elem=document.createElement('p');
			elem.innerHTML='<u>SHA256 hash of page source</u>';
			document.getElementById('divmain').appendChild(elem);

			var elem=document.createElement('pre');
			elem.innerText=pageanalysis.sha256hash;
			document.getElementById('divmain').appendChild(elem);

			var trusted=false
			if('hashes' in truststore) {
				for(var j=0; j<truststore.hashes.length; j++) {
					if(truststore.hashes[j]==pageanalysis.sha256hash) { trusted=true; }
				}
			}

			if(trusted) {
				var elem=document.createElement('span');
				elem.innerText='sha256 hash found in trust store'; 
				elem.className='greencolor';
				document.getElementById('divmain').appendChild(elem);
				iconcolor=2;
			} else {
				var elem=document.createElement('a');
				elem.value=pageanalysis.sha256hash;
				elem.innerText='add sha256 hash to trust store'; 
				elem.addEventListener('click', function() {
					addhashtotruststore(this.value)
					.then(function(pageanalysis){	
						alert('sha256 hash added to trust store.');
					});
				});
				document.getElementById('divmain').appendChild(elem);
			}

			var elem=document.createElement('hr');
			elem.className='orangecolor';
			document.getElementById('divmain').appendChild(elem);

			var elem=document.createElement('p');
			elem.innerHTML='<u>Signatures</u>';
			document.getElementById('divmain').appendChild(elem);

			if(pageanalysis.verifiedsignaturepublickeys.length==0) {
				var str='No signatures found for this page source.';
			} else if(pageanalysis.verifiedsignaturepublickeys.length==1) {
				var str='Verified signature of the page source was made using the following public key:';
			} else {
				var str='Verified signatures of the page source were made using the following public keys:';
			}
			var elem=document.createElement('h6');
			elem.innerText=str;
			document.getElementById('divmain').appendChild(elem);

			for(var i=0; i<pageanalysis.verifiedsignaturepublickeys.length; i++) {
				var elem=document.createElement('pre');
				elem.innerText='algorithm:' + JSON.stringify(pageanalysis.verifiedsignaturepublickeys[i].algorithm) + "\n" + wraplongstring(pageanalysis.verifiedsignaturepublickeys[i].keydata);
				document.getElementById('divmain').appendChild(elem);
				if(iconcolor==0) { iconcolor=1; }

				var trusted=false
				if('publickeys' in truststore) {
					for(var j=0; j<truststore.publickeys.length; j++) {
						if(truststore.publickeys[j].keydata==pageanalysis.verifiedsignaturepublickeys[i].keydata) { trusted=true; }
					}
				}

				if(trusted) {
					var elem=document.createElement('span');
					elem.innerText='public key found in trust store'; 
					elem.className='greencolor';
					document.getElementById('divmain').appendChild(elem);
					iconcolor=2;
				} else {
					var elem=document.createElement('a');
					var e=pageanalysis.verifiedsignaturepublickeys[i];
					delete e.trusted;
					elem.value=e;
					elem.innerText='add public key to trusted key store'; 
					elem.addEventListener('click', function() {
						addkeytotruststore(this.value)
						.then(function(pageanalysis){	
							alert('public key added to trusted key store.');
						});
					});
					document.getElementById('divmain').appendChild(elem);
				}

				if(i<pageanalysis.verifiedsignaturepublickeys.length-1) { 
					var elem=document.createElement('hr');
					elem.className='greycolor';
					document.getElementById('divmain').appendChild(elem);
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
}

function showtruststore() {
	divhead.style.display='block';	
	divmainlinks.style.display='none';
	divtruststorelinks.style.display='block';

	document.getElementById('divmain').style="text-align: left;";
	document.getElementById('divmain').innerHTML='';
	var elem=document.createElement('h4');
	elem.innerHTML='Trust Store';
	document.getElementById('divmain').appendChild(elem);

	browser.storage.local.get()
	.then(function(result){	
		var elem=document.createElement('p');
		elem.innerHTML='<u>Hashes</u>';
		document.getElementById('divmain').appendChild(elem);

		if('hashes' in result && result.hashes.length>0) {
			for(var i=0; i<result.hashes.length; i++) {
				var elem=document.createElement('pre');
				elem.innerText=result.hashes[i];
				document.getElementById('divmain').appendChild(elem);

				var elem=document.createElement('a');
				elem.value=result.hashes[i];
				elem.innerText='remove sha256 hash from trust store'; 
				elem.addEventListener('click', function() {
					removehashfromtruststore(this.value)
					.then(function(result){	
						alert('sha256 hash removed from trust store.');
						showtruststore();
					});
				});
				document.getElementById('divmain').appendChild(elem);
			}
		} else {
			var elem=document.createElement('p');
			elem.innerHTML='No hashes in trust store';
			document.getElementById('divmain').appendChild(elem);
		}

		var elem=document.createElement('hr');
		elem.className='orangecolor';
		document.getElementById('divmain').appendChild(elem);

		var elem=document.createElement('p');
		elem.innerHTML='<u>Public Keys</u>';
		document.getElementById('divmain').appendChild(elem);

		if('publickeys' in result && result.publickeys.length>0) {
			for(var i=0; i<result.publickeys.length; i++) {
				var elem=document.createElement('pre');
				elem.innerText='algorithm:' + JSON.stringify(result.publickeys[i].algorithm) + "\n" + wraplongstring(result.publickeys[i].keydata);
				document.getElementById('divmain').appendChild(elem);

				var elem=document.createElement('a');
				elem.value=result.publickeys[i].keydata;
				elem.innerText='remove key from trust store'; 
				elem.addEventListener('click', function() {
					removekeyfromtruststore(this.value)
					.then(function(result){	
						alert('key removed from trust store.');
						showtruststore();
					});
				});
				document.getElementById('divmain').appendChild(elem);


				if(i<result.publickeys.length-1) { 
					var elem=document.createElement('hr');
					elem.className='greycolor';
					document.getElementById('divmain').appendChild(elem);
				}
			}
		} else {
			var elem=document.createElement('p');
			elem.innerHTML='No public keys in trust store';
			document.getElementById('divmain').appendChild(elem);
		}

	});
}
