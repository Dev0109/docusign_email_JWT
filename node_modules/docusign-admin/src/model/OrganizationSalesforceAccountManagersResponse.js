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
    define(['ApiClient', 'model/OSAMRContact', 'model/OrganizationSalesforceAccountManagersResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OSAMRContact'), require('./OrganizationSalesforceAccountManagersResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationSalesforceAccountManagersResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.OSAMRContact, root.DocusignAdmin.OrganizationSalesforceAccountManagersResponse);
  }
}(this, function(ApiClient, OSAMRContact, OrganizationSalesforceAccountManagersResponse) {
  'use strict';


  /**
   * The OrganizationSalesforceAccountManagersResponse model module.
   * @module model/OrganizationSalesforceAccountManagersResponse
   */

  /**
   * Constructs a new <code>OrganizationSalesforceAccountManagersResponse</code>.
   * @alias module:model/OrganizationSalesforceAccountManagersResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationSalesforceAccountManagersResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationSalesforceAccountManagersResponse} obj Optional instance to populate.
   * @return {module:model/OrganizationSalesforceAccountManagersResponse} The populated <code>OrganizationSalesforceAccountManagersResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('account_id')) {
        obj['account_id'] = ApiClient.convertToType(data['account_id'], 'String');
      }
      if (data.hasOwnProperty('account_name')) {
        obj['account_name'] = ApiClient.convertToType(data['account_name'], 'String');
      }
      if (data.hasOwnProperty('account_type')) {
        obj['account_type'] = ApiClient.convertToType(data['account_type'], 'String');
      }
      if (data.hasOwnProperty('account_owner')) {
        obj['account_owner'] = OSAMRContact.constructFromObject(data['account_owner']);
      }
      if (data.hasOwnProperty('account_manager')) {
        obj['account_manager'] = OSAMRContact.constructFromObject(data['account_manager']);
      }
      if (data.hasOwnProperty('parent_account')) {
        obj['parent_account'] = OrganizationSalesforceAccountManagersResponse.constructFromObject(data['parent_account']);
      }
    }
    return obj;
  }

  /**
   * @member {String} account_id
   */
  exports.prototype['account_id'] = undefined;
  /**
   * @member {String} account_name
   */
  exports.prototype['account_name'] = undefined;
  /**
   * @member {String} account_type
   */
  exports.prototype['account_type'] = undefined;
  /**
   * @member {module:model/OSAMRContact} account_owner
   */
  exports.prototype['account_owner'] = undefined;
  /**
   * @member {module:model/OSAMRContact} account_manager
   */
  exports.prototype['account_manager'] = undefined;
  /**
   * @member {module:model/OrganizationSalesforceAccountManagersResponse} parent_account
   */
  exports.prototype['parent_account'] = undefined;



  return exports;
}));


