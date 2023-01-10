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
    define(['ApiClient', 'model/OrganizationAccountRequest'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OrganizationAccountRequest'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationAccountsRequest = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OrganizationAccountRequest);
  }
}(this, function(ApiClient, OrganizationAccountRequest) {
  'use strict';


  /**
   * The OrganizationAccountsRequest model module.
   * @module model/OrganizationAccountsRequest
   */

  /**
   * Constructs a new <code>OrganizationAccountsRequest</code>.
   * @alias module:model/OrganizationAccountsRequest
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationAccountsRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationAccountsRequest} obj Optional instance to populate.
   * @return {module:model/OrganizationAccountsRequest} The populated <code>OrganizationAccountsRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('accounts')) {
        obj['accounts'] = ApiClient.convertToType(data['accounts'], [OrganizationAccountRequest]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/OrganizationAccountRequest>} accounts
   */
  exports.prototype['accounts'] = undefined;



  return exports;
}));


