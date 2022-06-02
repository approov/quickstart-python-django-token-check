# Approov Token Integration Example

This Approov integration example is from where the code example for the [Approov token binding check quickstart](/docs/APPROOV_TOKEN_BINDING_QUICKSTART.md) is extracted, and you can use it as a playground to better understand how simple and easy it is to implement [Approov](https://approov.io) in a Python Django API server.

## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Requirements](#requirements)
* [Try the Approov Integration Example](#try-the-approov-integration-example)


## Why?

To lock down your API server to your mobile app. Please read the brief summary in the [Approov Overview](/OVERVIEW.md#why) at the root of this repo or visit our [website](https://approov.io/product) for more details.

[TOC](#toc---table-of-contents)


## How it works?

The Python Django API server is very simple and is defined in the project [src/approov-protected-server/token-binding-check/hello](/src/approov-protected-server/token-binding-check/hello). Take a look at the [approov_middleware.py](/src/approov-protected-server/token-binding-check/hello/approov_middleware.py) file, and search for the `verifyApproovToken()` and `verifyApproovTokenBinding()` functions to see the simple code for the check.

For more background on Approov, see the [Approov Overview](/OVERVIEW.md#how-it-works) at the root of this repo.

[TOC](#toc---table-of-contents)


## Requirements

To run this example you will need to have Python installed. If you don't have then please follow the official installation instructions from [here](https://wiki.python.org/moin/BeginnersGuide/Download) to download and install it.

[TOC](#toc---table-of-contents)


## Try the Approov Integration Example

First, you need to create the `.env` file. From the `src/approov-protected-server/token-binding-check/hello` folder execute:

```
cp .env.example .env
```

Second, you need to set the dummy secret in the `src/approov-protected-server/token-binding-check/hello/.env` file as explained [here](/TESTING.md#the-dummy-secret).

Next, you need to install the dependencies. From the `src/approov-protected-server/token-binding-check` folder execute:

```bash
python -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Now, you can run this example from the `src/approov-protected-server/token-binding-check` folder with:

```bash
python manage.py runserver 8002
```

> **NOTE:** If running inside a docker container use `0.0.0.0:8002`, otherwise Django will not answer requests from outside the container, like the ones you want to do from your browser.

Next, you can test that it works with:

```bash
curl -iX GET 'http://localhost:8002'
```

The response will be a `401` unauthorized request:

```text
HTTP/1.1 401 Unauthorized
Date: Wed, 23 Mar 2022 18:36:35 GMT
Server: WSGIServer/0.2 CPython/3.10.3
Content-Type: application/json
Connection: close

{}
```

The reason you got a `401` is because no Approoov token isn't provided in the headers of the request.

Finally, you can test that the Approov integration example works as expected with this [Postman collection](/TESTING.md#testing-with-postman) or with some cURL requests [examples](/TESTING.md#testing-with-curl).

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
