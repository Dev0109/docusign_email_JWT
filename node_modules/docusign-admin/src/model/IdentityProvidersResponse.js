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
    define(['ApiClient', 'model/IdentityProviderResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./IdentityProviderResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.IdentityProvidersResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.IdentityProviderResponse);
  }
}(this, function(ApiClient, IdentityProviderResponse) {
  'use strict';


  /**
   * The IdentityProvidersResponse model module.
   * @module model/IdentityProvidersResponse
   */

  /**
   * Constructs a new <code>IdentityProvidersResponse</code>.
   * @alias module:model/IdentityProvidersResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>IdentityProvidersResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/IdentityProvidersResponse} obj Optional instance to populate.
   * @return {module:model/IdentityProvidersResponse} The populated <code>IdentityProvidersResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('identity_providers')) {
        obj['identity_providers'] = ApiClient.convertToType(data['identity_providers'], [IdentityProviderResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/IdentityProviderResponse>} identity_providers
   */
  exports.prototype['identity_providers'] = undefined;



  return exports;
}));


