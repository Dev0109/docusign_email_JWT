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
    define(['ApiClient', 'model/CertificateResponse', 'model/RequiredAttributeMappingResponse', 'model/SettingResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./CertificateResponse'), require('./RequiredAttributeMappingResponse'), require('./SettingResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.Saml2IdentityProviderResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.CertificateResponse, root.DocusignAdmin.RequiredAttributeMappingResponse, root.DocusignAdmin.SettingResponse);
  }
}(this, function(ApiClient, CertificateResponse, RequiredAttributeMappingResponse, SettingResponse) {
  'use strict';


  /**
   * The Saml2IdentityProviderResponse model module.
   * @module model/Saml2IdentityProviderResponse
   */

  /**
   * Constructs a new <code>Saml2IdentityProviderResponse</code>.
   * @alias module:model/Saml2IdentityProviderResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>Saml2IdentityProviderResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/Saml2IdentityProviderResponse} obj Optional instance to populate.
   * @return {module:model/Saml2IdentityProviderResponse} The populated <code>Saml2IdentityProviderResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('issuer')) {
        obj['issuer'] = ApiClient.convertToType(data['issuer'], 'String');
      }
      if (data.hasOwnProperty('settings')) {
        obj['settings'] = ApiClient.convertToType(data['settings'], [SettingResponse]);
      }
      if (data.hasOwnProperty('certificates')) {
        obj['certificates'] = ApiClient.convertToType(data['certificates'], [CertificateResponse]);
      }
      if (data.hasOwnProperty('attribute_mappings')) {
        obj['attribute_mappings'] = ApiClient.convertToType(data['attribute_mappings'], [RequiredAttributeMappingResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {String} issuer
   */
  exports.prototype['issuer'] = undefined;
  /**
   * @member {Array.<module:model/SettingResponse>} settings
   */
  exports.prototype['settings'] = undefined;
  /**
   * @member {Array.<module:model/CertificateResponse>} certificates
   */
  exports.prototype['certificates'] = undefined;
  /**
   * @member {Array.<module:model/RequiredAttributeMappingResponse>} attribute_mappings
   */
  exports.prototype['attribute_mappings'] = undefined;



  return exports;
}));


