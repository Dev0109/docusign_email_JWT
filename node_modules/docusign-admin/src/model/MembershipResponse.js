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
    define(['ApiClient', 'model/MemberGroupResponse', 'model/PermissionProfileResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./MemberGroupResponse'), require('./PermissionProfileResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.MembershipResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.MemberGroupResponse, root.DocusignAdmin.PermissionProfileResponse);
  }
}(this, function(ApiClient, MemberGroupResponse, PermissionProfileResponse) {
  'use strict';


  /**
   * The MembershipResponse model module.
   * @module model/MembershipResponse
   */

  /**
   * Constructs a new <code>MembershipResponse</code>.
   * @alias module:model/MembershipResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>MembershipResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/MembershipResponse} obj Optional instance to populate.
   * @return {module:model/MembershipResponse} The populated <code>MembershipResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('email')) {
        obj['email'] = ApiClient.convertToType(data['email'], 'String');
      }
      if (data.hasOwnProperty('account_id')) {
        obj['account_id'] = ApiClient.convertToType(data['account_id'], 'String');
      }
      if (data.hasOwnProperty('external_account_id')) {
        obj['external_account_id'] = ApiClient.convertToType(data['external_account_id'], 'String');
      }
      if (data.hasOwnProperty('account_name')) {
        obj['account_name'] = ApiClient.convertToType(data['account_name'], 'String');
      }
      if (data.hasOwnProperty('is_external_account')) {
        obj['is_external_account'] = ApiClient.convertToType(data['is_external_account'], 'Boolean');
      }
      if (data.hasOwnProperty('status')) {
        obj['status'] = ApiClient.convertToType(data['status'], 'String');
      }
      if (data.hasOwnProperty('permission_profile')) {
        obj['permission_profile'] = PermissionProfileResponse.constructFromObject(data['permission_profile']);
      }
      if (data.hasOwnProperty('created_on')) {
        obj['created_on'] = ApiClient.convertToType(data['created_on'], 'Date');
      }
      if (data.hasOwnProperty('groups')) {
        obj['groups'] = ApiClient.convertToType(data['groups'], [MemberGroupResponse]);
      }
      if (data.hasOwnProperty('is_admin')) {
        obj['is_admin'] = ApiClient.convertToType(data['is_admin'], 'Boolean');
      }
    }
    return obj;
  }

  /**
   * @member {String} email
   */
  exports.prototype['email'] = undefined;
  /**
   * @member {String} account_id
   */
  exports.prototype['account_id'] = undefined;
  /**
   * @member {String} external_account_id
   */
  exports.prototype['external_account_id'] = undefined;
  /**
   * @member {String} account_name
   */
  exports.prototype['account_name'] = undefined;
  /**
   * @member {Boolean} is_external_account
   */
  exports.prototype['is_external_account'] = undefined;
  /**
   * @member {String} status
   */
  exports.prototype['status'] = undefined;
  /**
   * @member {module:model/PermissionProfileResponse} permission_profile
   */
  exports.prototype['permission_profile'] = undefined;
  /**
   * @member {Date} created_on
   */
  exports.prototype['created_on'] = undefined;
  /**
   * @member {Array.<module:model/MemberGroupResponse>} groups
   */
  exports.prototype['groups'] = undefined;
  /**
   * @member {Boolean} is_admin
   */
  exports.prototype['is_admin'] = undefined;



  return exports;
}));


