# Approov Token Integration Example

This Approov integration example is from where the code example for the [Approov token check quickstart](/docs/APPROOV_TOKEN_QUICKSTART.md) is extracted, and you can use it as a playground to better understand how simple and easy it is to implement [Approov](https://approov.io) in a Python Django API server.

## TOC - Table of Contents

* [Why?](#why)
* [How it Works?](#how-it-works)
* [Requirements](#requirements)
* [Try the Approov Integration Example](#try-the-approov-integration-example)


## Why?

To lock down your API server to your mobile app. Please read the brief summary in the [README](/README.md#why) at the root of this repo or visit our [website](https://approov.io/product.html) for more details.

[TOC](#toc---table-of-contents)
just

## How it works?

The Python Django API server is very simple and is defined in the project [src/approov-protected-server/token-check/hello](/src/approov-protected-server/token-check/hello). Take a look at the [approov_middleware.py](/src/approov-protected-server/token-check/hello/approov_middleware.py) file, and search for the `verifyApproovToken()` function to see the simple code for the check.

For more background on Approov, see the overview in the [README](/README.md#how-it-works) at the root of this repo.

[TOC](#toc---table-of-contents)


## Requirements

To run this example you will need to have Python installed. If you don't have then please follow the official installation instructions from [here](https://wiki.python.org/moin/BeginnersGuide/Download) to download and install it.

[TOC](#toc---table-of-contents)


## Try the Approov Integration Example

First, you need to create the `.env` file. From the `src/approov-protected-server/token-check/hello` folder execute:

```
cp .env.example .env
```

Second, you need to set the dummy secret in the `src/approov-protected-server/token-check/hello/.env` file as explained [here](/README.md#the-dummy-secret).

Next, you need to install the dependencies. From the `src/approov-protected-server/token-check` folder execute:

```text
python -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Now, you can run this example from the `src/approov-protected-server/token-check` folder with:

```text
python manage.py runserver 8002
```

> **NOTE:** If running inside a docker container use `0.0.0.0:8002`, otherwise Django will not answer requests from outside the container, like the ones you want to do from your browser.

Finally, you can test that the Approov integration example works as expected with this [Postman collection](/README.md#testing-with-postman) or with some cURL requests [examples](/README.md#testing-with-curl).

[TOC](#toc---table-of-contents)
