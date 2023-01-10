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
    define(['ApiClient', 'model/GroupRequest', 'model/PermissionProfileRequest'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./GroupRequest'), require('./PermissionProfileRequest'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.UpdateMembershipRequest = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.GroupRequest, root.DocusignAdmin.PermissionProfileRequest);
  }
}(this, function(ApiClient, GroupRequest, PermissionProfileRequest) {
  'use strict';


  /**
   * The UpdateMembershipRequest model module.
   * @module model/UpdateMembershipRequest
   */

  /**
   * Constructs a new <code>UpdateMembershipRequest</code>.
   * @alias module:model/UpdateMembershipRequest
   * @class
   * @param accountId {String} 
   */
  var exports = function(accountId) {
    var _this = this;

    _this['account_id'] = accountId;
  };

  /**
   * Constructs a <code>UpdateMembershipRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UpdateMembershipRequest} obj Optional instance to populate.
   * @return {module:model/UpdateMembershipRequest} The populated <code>UpdateMembershipRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('account_id')) {
        obj['account_id'] = ApiClient.convertToType(data['account_id'], 'String');
      }
      if (data.hasOwnProperty('permission_profile')) {
        obj['permission_profile'] = PermissionProfileRequest.constructFromObject(data['permission_profile']);
      }
      if (data.hasOwnProperty('groups')) {
        obj['groups'] = ApiClient.convertToType(data['groups'], [GroupRequest]);
      }
      if (data.hasOwnProperty('company_name')) {
        obj['company_name'] = ApiClient.convertToType(data['company_name'], 'String');
      }
      if (data.hasOwnProperty('job_title')) {
        obj['job_title'] = ApiClient.convertToType(data['job_title'], 'String');
      }
      if (data.hasOwnProperty('send_activation')) {
        obj['send_activation'] = ApiClient.convertToType(data['send_activation'], 'Boolean');
      }
      if (data.hasOwnProperty('access_code')) {
        obj['access_code'] = ApiClient.convertToType(data['access_code'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} account_id
   */
  exports.prototype['account_id'] = undefined;
  /**
   * @member {module:model/PermissionProfileRequest} permission_profile
   */
  exports.prototype['permission_profile'] = undefined;
  /**
   * @member {Array.<module:model/GroupRequest>} groups
   */
  exports.prototype['groups'] = undefined;
  /**
   * @member {String} company_name
   */
  exports.prototype['company_name'] = undefined;
  /**
   * @member {String} job_title
   */
  exports.prototype['job_title'] = undefined;
  /**
   * @member {Boolean} send_activation
   */
  exports.prototype['send_activation'] = undefined;
  /**
   * @member {String} access_code
   */
  exports.prototype['access_code'] = undefined;



  return exports;
}));


