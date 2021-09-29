PUBLIC KEY INFRASTRUCTURE LAB
------------------------------

#### Intro

My name is Keith Sabine and I will be working through this SEED security lab as part of my Undergrad CS studies.

#### Some Notes
All of the machine configurations are available on the SEED website.[PKI LAB](https://seedsecuritylabs.org/Labs_20.04/Crypto/Crypto_PKI/). I will only be posting my progress and observations as I work through the lab and answer the questions it requires. I set up the SEED VM using the Ubuntu 20.04 VM config. I will be completing both Tasks 1 through 5.

#### Lab Environment
Download the Labsetup.zip from the [PKI LAB](https://seedsecuritylabs.org/Labs_20.04/Crypto/Crypto_PKI/) and run the `dcbuild` alias followed by the `dcup` to get your containers running for the lab. For this lab run the tasks on the VM, but use the container to host the apache web server. We also need to edit in a couple entries to the /etc/hosts folder on the VM.

### LAB TASKS

***NOTE*** For the lab we will need to make sure our VM has the correct DNS entry for the name of the website we are creating on our webserver otherwise we won't be able to connect. I added in the example website as well as the one we will be creating. This will be in the /etc/hosts file on your Ubuntu VM.

```
10.9.0.80 www.bank32.com
10.9.0.80 www.sabinek2021.com
```

#### 3.1 Task 1: Becoming a Certificate Authority
---------------------------------------------------
We need to generate a self-signed certificate.

```
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
-keyout ca.key -out ca.crt
```
Next we need to generate two files.

index.txt --- An empty text file

serial --- Stores a number

This command generates the ca.key and ca.crt file. The private key for our CA (ca.key) and the public key certificate (ca.crt).

Additional commands can be used to generate the information openssl req will prompt for.

Taking a look at the X.509 certification we generated we can see the different fields of it.
The version number, Serial number, Signature algortihm ID, Issuer name, Validity period (not before, not after) Subject name, Subject public key information( the algorithm for public key and the Subject public key), The issuer unique identifier, the subject unique Identifier, the extensions, the Certificate Signature algorithm, and finally the certificate signature. 

In version 3 of X.509 the extension was added Basic Constraints. This field specifies whether the entity can be used as a CA and, if so, the number of subordinate CAs that can exist beneath it in the certificate chain.

Here we can see the constraints of our certificate. Which is as a CA.

![x509constraint](img/x509constraint.png)

We know that this certificate is self signed by looking at the issuer field of the certificate

![x509issuer](img/x509issuer.png)

Identifying the values in the certificate file:

We have the Modulus of the RSA algorithm in our certificate file as well as the public exponent stored. This is the 'n' value and the 'e' value respectivelying the `openssl rsa -in ca.key -text -noout`

![rsapublic](img/rsapublic.png)

If we want to get more information we need to access the the password protected key file. This will give us the rest of the values needed to perform the RSA encryption algortihm

n the modulo value calculated by multiplying two primes p and q:

![modulus](img/modulus.png)

We can find p and q under the prime1 and prime2 fields:

![primes](img/primes.png)

Our public and private exponents are the values e, and d respectively:

![exponents](img/exponents.png)

### Task 2: Generating a Certificate Request for your Web Server
------------------------------------------------------------------

We are going to create a webserver called sabinek2021. We need to get a public-key certificate from our newly made CA. We will need to generate a Certificate Signing Request, which includes the company's name and information, send the request to the CA which will verify the identity information of the request and grant a certificate.

I ran this command to generate the key of my sabinek2021 webserver, the lab instructs us further to add in some alternative domains to be accepted with the same certificate so I will add in the `-addext "subject AltName = [Names]':

```
openssl req -newkey rsa:2048 -sha256 \
-keyout server.key -out server.csr \
-subj "/CN=www.sabinek2021.com/O=sabinek2021 Inc./C=CA" \
-addext "subjectAltName = DNS: www.sabinek2021.com, \
			  DNS: www.sabinek2021A.com, \
			  DNS: www.sabinek2021B.com"\
-passout pass:dees
```
So lets take a look at the files we created for our webserver's certificate.

Run the commands:
```
openssl req -in server.csr -text -noout
openssl rsa -in server.key -text -noout
```
So we have generated the requests lets take a look:

![csr](img/csr.png)

We can see the request of my webserver here.

![serverkey](img/serverkey.png)

And here is (part) of the server key.

### TASK 3: Generating a Certificate for your server
------------------------------------------------------

We need to turn our CSR into a certificate for our webserver signed by our made up Certificate authority. 

We run the following openssl command to accomplish this:
`
openssl ca -config myCA_openssl.cnf -policy policy_anything \
-md sha256 -days 3650 \
-in server.csr -out server.crt -batch \
-cert ca.crt -keyfile ca.key
`

Specifically we use our copied config file, not the systems own and we use "policy_anything" when defining the policy. policy_anything is not the default policyy, it has less restrictions than the default when matching the CSR to the CA's certificate. 

We need to go back into our config file and uncomment the copy_extensions line, this will allow us to copy the extension fields to the webserver certificate.

**NOTE** I had to restart the process here because I had not set up the directories properly. Make sure to read your config file and manual carefully!! You need to set up the proper directories and files in order for our openssl config file to properly function. After I got it all sorted out I was able to create the certificate for my webserver and it includes all of the domain names I specified.

![servercert](img/servercert.png)


### Task 4: Deploying Certificate in an Apache-Based HTTPS Website
--------------------------------------------------------------------

We need to create our files on the docker container setting up the sabinek2021 webserver. We need to create a ssl config file for our server first. this will specify where our keys are stored, where the website's files are stored and where the certificate is stored as well.

![sslconf](img/sslconf.png)

I have moved the server.crt and the server.key into the /certs directory on the Host container from the VM, refer to the VM instructions on how to do this (shared /volumes directory)

The next steps required to make the container's website work we need to run some commands with apache.

```
a2enmod ssl // enables the SSL module
a2ensite \[yourconfig\]_apache_ssl // This enables the sites in the config file

service apache2 start //Start the server
```

When you start the apache2 server it will prompt you to provide the password for the key and once entered the website will start up. 

***NOTE*** again make sure you have configured the /etc/hosts file on your VM to properly configure the DNS to match www.[yourservername].com to the container machine's IP address: 10.9.0.80

We can now go to the website. Firefox (or your browser) will flag the site's certificate as untrustworthy. This is a good feature for the browser to have because so far it has been easy to become a CA, we now know that there are a list of "trusted" CA that come with the browser and they can be viewed in firefox by typing: `about:preferences#privacy` and going to the View Certificates button at the bottom of the page.

We need to add our CA certificate file to this list in order for our browser to navigate to the page we have set up. Once all these steps are complete you should be able to browse to your site and inspect its certificate (the one we created)

![browse](img/browse.png)

Clicking on the lock icon in the address bar we can view our site's certificate as well as the issuing authority's certificate

![sitecert](img/sitecert.png)

![authcert](img/authcert.png)

### TASK 5: Launching a Man-In-The-Middle Attack
-------------------------------------------------

So how does the PKI defeat MITM(Man-In-The-Middle) attacks? 

![mitmfig](img/mitmfig.png)

We will try the method of attack here. Firstly I need to make the webserver container have a local host with a popular website's name. Lets try https://www.tdcanadatrust.com

I will create a website on the apache server with that domain name, using our self signed certificate to validate it. This will obviosuly be an invalid certificate, but the point here is to show that we can route a victim's traffic to our webserver.

Once we set up the https://www.tdcanadatrust.com virtualhost with apache wwe also need to modify the /etc/hosts folder on our VM machine to emulate the result of DNS cache poisoning and reroute the VM's traffic to our webserver. 

The browser will then take us to https://www.tdcanadatrust.com, but the https will first be routed through our machine.

We can see evidence that the requests are being sent to our webserver by using wireshark over its network interface

![mitmtraffic](img/mitmtraffic.png)

But our browser will warn us that the certificate we have does not match the domain name. Our certificate was registered with www.sabinek2021.com, www.sabinek2021A.com, and www.sabinek2021B.com, not to www.tdcanadatrust.com. 

![mitmsite](img/mitmsite.png)

We have already added an exception to our CA in our browser so the traffic should go through to any certificate signed by our bogus CA. If we were to go through the process of signing another fake certificate for https://www.tdcanadatrust.com AND simulate the DNS poisoning then we would receive no warning and proceed directly to the fake webpage we are hosting on the server on the victim machine.


### TASK 6: Launching a Man-In-The-Middle Attack with a Compromised CA
------------------------------------------------------------------------

So what if the CA is compromised and we sign a certificate for https://www.tdcanadatrust.com with our CA?

First we will need to go through the process. We need to create a certificate and self-sign it with our compromised CA in order to get the browser to navigate directly to our website without any warnings given by the browser.

##### Step 1: Create a certificate signed by the compromised CA.

Say we have the private key of a certificate authority, this will allow us to create any number of certificates that will appear legitamately signed by our CA.

We first need to create the certificate and key of the bogus webpage. So we will spoof credentials of tdcanadatrust and use them with our openssl command.

and we succeed! We now own a certificate claiming to be owned by www.tdcanadatrust.com and can utilize it on our webserver

![compromisedCA](img/compromisedCA.png)

Now go back to the apache server and edit the config we used in the last task to use our new certificate and key, enable the site, and restart the apache2 service. We should now be able to navigate to our fake website owned by 'TD Canada Trust'

![compromisedsite](img/compromisedsite.png)


#### Conclusion

PKI gives us a powerful tool to provide authentication that the communications we are sending and receiving are in fact valid. This infrastructure is not perfect and has been the targets of attacks in the past. Just look at the case of [Diginotar](https://www.wired.com/2011/09/diginotar-bankruptcy/) , a Certificate authority who was compromised in 2011 and went bankrupt as a result. So long as we trust the Certificate Authority, we know that the communication is secure and we are not being a victim of a man-in-the-middle attack. So check your certificates!
 
