# The Official DocuSign Admin Node Client

[![NPM version][npm-image]][npm-url]
[![NPM downloads][downloads-image]][downloads-url]
[![Build status][travis-image]][travis-url]
[![Coverage Status][coveralls-image]][coveralls-url]

[NPM module](https://www.npmjs.com/package/docusign-admin) that wraps the <a href="https://www.docusign.com">DocuSign</a> Admin API

[Documentation about the DocuSign Admin API](https://developers.docusign.com/docs/admin-api)

<!---
[Changelog](./CHANGELOG.md)
commented out
-->


## Requirements
- Node 4
- Free [Developer Account](https://go.docusign.com/sandbox/productshot/?elqCampaignId=16531)
- DocuSign Admin account connected to your Developer account. [Here is how to create a developer account](https://go.docusign.com/o/sandbox/?ga=2.70927056.1363819232.1590515244-192278368.1546193875&ECID=20890&elqCampaignId=20890&LS=NA_DEV_BOTH_BetaSite_2020-05&utm_campaign=NA_DEV_BOTH_BetaSite_2020-05&Channel=DDCUS000016968056&cName=DocuSign.com&postActivateUrl=https://developers.docusign.com/)

## Compatibility

- Node 4+

## Note:

This SDK will soon be provided as open-source for cases where you would like to make additional changes that the SDK does not provide out-of-the-box. If you simply want to use the SDK with any of the examples shown in the [Developer Center](https://developers.docusign.com/docs/admin-api/how-to/), follow the installation instructions below.

## Installation

## NPM:

1. Open your preferred command-line console, then navigate to your project.
2. In the console, type the following commands:  
   **npm install docusign-admin -save**


## Dependencies

This client has the following external dependencies:

### Minimum:

- Superagent 3.8.2

### Optional:

- Async v2.6.2
- Jsonwebtoken v8.2.0
- Passport-oauth2
- Path

## Code Examples

### Launchers

DocuSign provides a sample application referred to as a [Launcher](https://github.com/docusign/code-examples-node/). The Launcher contains a set of 6 common use cases and associated source files. These examples use DocuSign&#39;s [Authorization Code Grant](https://developers.docusign.com/platform/auth/authcode/authcode-get-token/) flow.

## OAuth Implementations

For details regarding which type of OAuth grant will work best for your DocuSign integration, see the [OrgAdmin API Authentication Overview](https://developers.docusign.com/docs/orgadmin-api/orgadmin101/auth/) guide located on the [DocuSign Developer Center](https://developers.docusign.com/).

For security purposes, DocuSign recommends using the [Authorization Code Grant](https://developers.docusign.com/platform/auth/authcode/authcode-get-token/) or [JWT](https://developers.docusign.com/platform/auth/jwt/) flow.

There are other use-case scenarios, such as **single-page applications** (SPA) that use **Cross-Origin Resource Sharing** (CORS), or where there may not be a user to interact with your Service Account. For these use cases, DocuSign also supports [JWT](https://developers.docusign.com/platform/auth/jwt/jwt-get-token/) and [Implicit](https://developers.docusign.com/platform/auth/implicit/implicit-get-token/) grants. For Code eExamples, see the links below:


## Support

Log issues against this client through GitHub. We also have an [active developer community on Stack Overflow](http://stackoverflow.com/questions/tagged/docusignapi).

## License

The DocuSign Admin Node Client is licensed under the [MIT License](https://github.com/docusign/docusign-orgadmin-node-client/blob/master/LICENSE).

[npm-image]: https://img.shields.io/npm/v/docusign-orgadmin.svg?style=flat
[npm-url]: https://npmjs.org/package/docusign-orgadmin
[downloads-image]: https://img.shields.io/npm/dm/docusign-orgadmin.svg?style=flat
[downloads-url]: https://npmjs.org/package/docusign-orgadmin
[travis-image]: https://img.shields.io/travis/docusign/docusign-orgadmin-node-client.svg?style=flat
[travis-url]: https://travis-ci.org/docusign/docusign-orgadmin-node-client
[coveralls-image]: https://coveralls.io/repos/github/docusign/docusign-orgadmin-node-client/badge.svg?branch=master
[coveralls-url]: https://coveralls.io/github/docusign/docusign-orgadmin-node-client?branch=master
