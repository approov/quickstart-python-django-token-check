# Unprotected Server Example

The unprotected example is the base reference to build the [Approov protected servers](/src/approov-protected-server/). This a very basic Hello World server.


## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Requirements](#requirements)
* [Try It](#try-it)


## Why?

To be the starting building block for the [Approov protected servers](/src/approov-protected-server/), that will show you how to lock down your API server to your mobile app. Please read the brief summary in the [Approov Overview](/OVERVIEW.md#why) at the root of this repo or visit our [website](https://approov.io/product) for more details.

[TOC](#toc---table-of-contents)


## How it works?

The Python Django server is very simple and is defined in the project located at [src/unprotected-server/hello](/src/unprotected-server/hello).

The server only replies to the endpoint `/` with the message:

```json
{"message": "Hello, World!"}
```

[TOC](#toc---table-of-contents)


## Requirements

To run this example you will need to have Python 3 installed. If you don't have then please follow the official installation instructions from [here](https://wiki.python.org/moin/BeginnersGuide/Download) to download and install it.

[TOC](#toc---table-of-contents)


## Try It

First, you need to create the `.env` file. From the `src/unprotected-server/hello` folder execute:

```
cp .env.example .env
```

Next, you need to install the dependencies. From the `src/unprotected-server` folder execute:

```text
python -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Now, you can run this example from the `src/unprotected-server` folder with:

```text
python manage.py runserver 8002
```

> **NOTE:** If running inside a docker container use `0.0.0.0:8002`, otherwise Django will not answer requests from outside the container, like the ones you want to do from your browser.

Finally, you can test that it works with:

```text
curl -iX GET 'http://localhost:8002'
```

The response will be:

```text
HTTP/1.1 200 OK
Date: Wed, 30 Sep 2020 15:04:20 GMT
Server: WSGIServer/0.2 CPython/3.8.6
Content-Type: application/json
X-Frame-Options: DENY
Content-Length: 28
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin

{"message": "Hello, World!"}
```

[TOC](#toc---table-of-contents)


## Issues

If you find any issue while following our instructions then just report it [here](https://github.com/approov/quickstart-python-django-token-check/issues), with the steps to reproduce it, and we will sort it out and/or guide you to the correct path.

[TOC](#toc---table-of-contents)


## Useful Links

If you wish to explore the Approov solution in more depth, then why not try one of the following links as a jumping off point:

* [Approov Free Trial](https://approov.io/signup)(no credit card needed)
* [Approov Get Started](https://approov.io/product/demo)
* [Approov QuickStarts](https://approov.io/docs/latest/approov-integration-examples/)
* [Approov Docs](https://approov.io/docs)
* [Approov Blog](https://approov.io/blog/)
* [Approov Resources](https://approov.io/resource/)
* [Approov Customer Stories](https://approov.io/customer)
* [Approov Support](https://approov.io/contact)
* [About Us](https://approov.io/company)
* [Contact Us](https://approov.io/contact)

[TOC](#toc---table-of-contents)
