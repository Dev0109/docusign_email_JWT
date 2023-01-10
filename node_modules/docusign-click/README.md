# The Official DocuSign Click Node Client SDK

[![NPM version][npm-image]][npm-url]
[![NPM downloads][downloads-image]][downloads-url]
[![Build status][travis-image]][travis-url]
[![Coverage Status][coveralls-image]][coveralls-url]

[NPM module](https://www.npmjs.com/package/docusign-click)

[Documentation about the DocuSign Click API](https://developers.docusign.com/docs/click-api)

<!---
[Changelog](./CHANGELOG.md)
commented out
-->


## Requirements
- Node 4
- Free [Developer Account](https://go.docusign.com/sandbox/productshot/?elqCampaignId=16531)

## Compatibility

- Node 4+

## Installation

This SDK is provided as open source, which enables you to customize its functionality to suit your particular use case. To do so, download or clone the repository. If the SDK’s given functionality meets your integration needs, or if you simply want to use the SDK with any of the examples shown in the [Developer Center](https://developers.docusign.com/docs/click-api/how-to/), you merely need to install it by following the instructions below.

## NPM:

1. Open your preferred command-line console, then navigate to your project.
2. In the console, type the following commands:  
   **npm install docusign-click -save**


## Dependencies

This client has the following external dependencies:

### Minimum:

- Superagent 3.8.2

### Optional:

- Async v2.6.2
- Jsonwebtoken v8.2.0
- Passport-oauth2
- Path

## Code examples

DocuSign provides a sample application code referred to as a [Launcher](https://github.com/docusign/code-examples-node). The Launcher includes, besides a full set of eSignature code examples, a set of code examples and associated source files for five common Click use cases. These examples can use either the [Authorization Code Grant](https://developers.docusign.com/platform/auth/authcode/) or [JSON Web Token (JWT) Grant](https://developers.docusign.com/platform/auth/jwt/) authentication flow.

## OAuth implementations

For details regarding which type of OAuth grant will work best for your DocuSign integration, see the [Choose OAuth Type](https://developers.docusign.com/platform/auth/choose/) guide located on the [DocuSign Developer Center](https://developers.docusign.com/).

For security purposes, DocuSign recommends using the [Authorization Code Grant](https://developers.docusign.com/platform/auth/authcode/) flow.

## Support

Log issues against this client through GitHub. We also have an [active developer community on Stack Overflow](http://stackoverflow.com/questions/tagged/docusignapi).

## License

The DocuSign Click Node Client is licensed under the [MIT License](https://github.com/docusign/docusign-click-node-client/blob/master/LICENSE).

[npm-image]: https://img.shields.io/npm/v/docusign-click.svg?style=flat
[npm-url]: https://npmjs.org/package/docusign-click
[downloads-image]: https://img.shields.io/npm/dm/docusign-click.svg?style=flat
[downloads-url]: https://npmjs.org/package/docusign-click
[travis-image]: https://img.shields.io/travis/docusign/docusign-click-node-client.svg?style=flat
[travis-url]: https://travis-ci.org/docusign/docusign-node-client
[coveralls-image]: https://coveralls.io/repos/github/docusign/DocuSign-Node-Client/badge.svg?branch=master
[coveralls-url]: https://coveralls.io/github/docusign/DocuSign-Node-Client?branch=master

### Additional resources
* [DocuSign Developer Center](https://developers.docusign.com)
* [DocuSign API on Twitter](https://twitter.com/docusignapi)
* [DocuSign For Developers on LinkedIn](https://www.linkedin.com/showcase/docusign-for-developers/)
* [DocuSign For Developers on YouTube](https://www.youtube.com/channel/UCJSJ2kMs_qeQotmw4-lX2NQ)