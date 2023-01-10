/**
 * DocuSign Admin API
 * An API for an organization administrator to manage organizations, accounts and users
 *
 * OpenAPI spec version: v2.1
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/LinkResponse', 'model/Saml2IdentityProviderResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./LinkResponse'), require('./Saml2IdentityProviderResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.IdentityProviderResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.LinkResponse, root.DocusignAdmin.Saml2IdentityProviderResponse);
  }
}(this, function(ApiClient, LinkResponse, Saml2IdentityProviderResponse) {
  'use strict';


  /**
   * The IdentityProviderResponse model module.
   * @module model/IdentityProviderResponse
   */

  /**
   * Constructs a new <code>IdentityProviderResponse</code>.
   * @alias module:model/IdentityProviderResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>IdentityProviderResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/IdentityProviderResponse} obj Optional instance to populate.
   * @return {module:model/IdentityProviderResponse} The populated <code>IdentityProviderResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('friendly_name')) {
        obj['friendly_name'] = ApiClient.convertToType(data['friendly_name'], 'String');
      }
      if (data.hasOwnProperty('auto_provision_users')) {
        obj['auto_provision_users'] = ApiClient.convertToType(data['auto_provision_users'], 'Boolean');
      }
      if (data.hasOwnProperty('type')) {
        obj['type'] = ApiClient.convertToType(data['type'], 'String');
      }
      if (data.hasOwnProperty('saml_20')) {
        obj['saml_20'] = Saml2IdentityProviderResponse.constructFromObject(data['saml_20']);
      }
      if (data.hasOwnProperty('links')) {
        obj['links'] = ApiClient.convertToType(data['links'], [LinkResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
  /**
   * @member {String} friendly_name
   */
  exports.prototype['friendly_name'] = undefined;
  /**
   * @member {Boolean} auto_provision_users
   */
  exports.prototype['auto_provision_users'] = undefined;
  /**
   * @member {String} type
   */
  exports.prototype['type'] = undefined;
  /**
   * @member {module:model/Saml2IdentityProviderResponse} saml_20
   */
  exports.prototype['saml_20'] = undefined;
  /**
   * @member {Array.<module:model/LinkResponse>} links
   */
  exports.prototype['links'] = undefined;



  return exports;
}));


