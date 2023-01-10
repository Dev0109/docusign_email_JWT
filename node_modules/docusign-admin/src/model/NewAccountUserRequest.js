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
    root.DocusignAdmin.NewAccountUserRequest = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.GroupRequest, root.DocusignAdmin.PermissionProfileRequest);
  }
}(this, function(ApiClient, GroupRequest, PermissionProfileRequest) {
  'use strict';


  /**
   * The NewAccountUserRequest model module.
   * @module model/NewAccountUserRequest
   */

  /**
   * Constructs a new <code>NewAccountUserRequest</code>.
   * @alias module:model/NewAccountUserRequest
   * @class
   * @param email {String} 
   */
  var exports = function(email) {
    var _this = this;

    _this['email'] = email;
  };

  /**
   * Constructs a <code>NewAccountUserRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/NewAccountUserRequest} obj Optional instance to populate.
   * @return {module:model/NewAccountUserRequest} The populated <code>NewAccountUserRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('permission_profile')) {
        obj['permission_profile'] = PermissionProfileRequest.constructFromObject(data['permission_profile']);
      }
      if (data.hasOwnProperty('groups')) {
        obj['groups'] = ApiClient.convertToType(data['groups'], [GroupRequest]);
      }
      if (data.hasOwnProperty('user_name')) {
        obj['user_name'] = ApiClient.convertToType(data['user_name'], 'String');
      }
      if (data.hasOwnProperty('first_name')) {
        obj['first_name'] = ApiClient.convertToType(data['first_name'], 'String');
      }
      if (data.hasOwnProperty('last_name')) {
        obj['last_name'] = ApiClient.convertToType(data['last_name'], 'String');
      }
      if (data.hasOwnProperty('email')) {
        obj['email'] = ApiClient.convertToType(data['email'], 'String');
      }
      if (data.hasOwnProperty('default_account_id')) {
        obj['default_account_id'] = ApiClient.convertToType(data['default_account_id'], 'String');
      }
      if (data.hasOwnProperty('language_culture')) {
        obj['language_culture'] = ApiClient.convertToType(data['language_culture'], 'String');
      }
      if (data.hasOwnProperty('selected_languages')) {
        obj['selected_languages'] = ApiClient.convertToType(data['selected_languages'], 'String');
      }
      if (data.hasOwnProperty('access_code')) {
        obj['access_code'] = ApiClient.convertToType(data['access_code'], 'String');
      }
      if (data.hasOwnProperty('federated_status')) {
        obj['federated_status'] = ApiClient.convertToType(data['federated_status'], 'String');
      }
      if (data.hasOwnProperty('auto_activate_memberships')) {
        obj['auto_activate_memberships'] = ApiClient.convertToType(data['auto_activate_memberships'], 'Boolean');
      }
    }
    return obj;
  }

  /**
   * @member {module:model/PermissionProfileRequest} permission_profile
   */
  exports.prototype['permission_profile'] = undefined;
  /**
   * @member {Array.<module:model/GroupRequest>} groups
   */
  exports.prototype['groups'] = undefined;
  /**
   * @member {String} user_name
   */
  exports.prototype['user_name'] = undefined;
  /**
   * @member {String} first_name
   */
  exports.prototype['first_name'] = undefined;
  /**
   * @member {String} last_name
   */
  exports.prototype['last_name'] = undefined;
  /**
   * @member {String} email
   */
  exports.prototype['email'] = undefined;
  /**
   * @member {String} default_account_id
   */
  exports.prototype['default_account_id'] = undefined;
  /**
   * @member {String} language_culture
   */
  exports.prototype['language_culture'] = undefined;
  /**
   * @member {String} selected_languages
   */
  exports.prototype['selected_languages'] = undefined;
  /**
   * @member {String} access_code
   */
  exports.prototype['access_code'] = undefined;
  /**
   * @member {String} federated_status
   */
  exports.prototype['federated_status'] = undefined;
  /**
   * @member {Boolean} auto_activate_memberships
   */
  exports.prototype['auto_activate_memberships'] = undefined;



  return exports;
}));


