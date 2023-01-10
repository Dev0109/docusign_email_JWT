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
    root.DocusignAdmin.OrganizationAccountRequest = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The OrganizationAccountRequest model module.
   * @module model/OrganizationAccountRequest
   */

  /**
   * Constructs a new <code>OrganizationAccountRequest</code>.
   * @alias module:model/OrganizationAccountRequest
   * @class
   * @param accountId {String} 
   */
  var exports = function(accountId) {
    var _this = this;

    _this['account_id'] = accountId;
  };

  /**
   * Constructs a <code>OrganizationAccountRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationAccountRequest} obj Optional instance to populate.
   * @return {module:model/OrganizationAccountRequest} The populated <code>OrganizationAccountRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('account_id')) {
        obj['account_id'] = ApiClient.convertToType(data['account_id'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} account_id
   */
  exports.prototype['account_id'] = undefined;



  return exports;
}));


