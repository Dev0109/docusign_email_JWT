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
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationAccountResponse = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The OrganizationAccountResponse model module.
   * @module model/OrganizationAccountResponse
   */

  /**
   * Constructs a new <code>OrganizationAccountResponse</code>.
   * @alias module:model/OrganizationAccountResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationAccountResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationAccountResponse} obj Optional instance to populate.
   * @return {module:model/OrganizationAccountResponse} The populated <code>OrganizationAccountResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('external_account_id')) {
        obj['external_account_id'] = ApiClient.convertToType(data['external_account_id'], 'Number');
      }
      if (data.hasOwnProperty('site_id')) {
        obj['site_id'] = ApiClient.convertToType(data['site_id'], 'Number');
      }
    }
    return obj;
  }

  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Number} external_account_id
   */
  exports.prototype['external_account_id'] = undefined;
  /**
   * @member {Number} site_id
   */
  exports.prototype['site_id'] = undefined;



  return exports;
}));


