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
    define(['ApiClient', 'model/DSGroupRequest', 'model/ProductPermissionProfileRequest'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./DSGroupRequest'), require('./ProductPermissionProfileRequest'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.NewMultiProductUserAddRequest = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DSGroupRequest, root.DocusignAdmin.ProductPermissionProfileRequest);
  }
}(this, function(ApiClient, DSGroupRequest, ProductPermissionProfileRequest) {
  'use strict';


  /**
   * The NewMultiProductUserAddRequest model module.
   * @module model/NewMultiProductUserAddRequest
   */

  /**
   * Constructs a new <code>NewMultiProductUserAddRequest</code>.
   * @alias module:model/NewMultiProductUserAddRequest
   * @class
   * @param productPermissionProfiles {Array.<module:model/ProductPermissionProfileRequest>} 
   * @param email {String} 
   */
  var exports = function(productPermissionProfiles, email) {
    var _this = this;

    _this['product_permission_profiles'] = productPermissionProfiles;    _this['email'] = email;
  };

  /**
   * Constructs a <code>NewMultiProductUserAddRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/NewMultiProductUserAddRequest} obj Optional instance to populate.
   * @return {module:model/NewMultiProductUserAddRequest} The populated <code>NewMultiProductUserAddRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('product_permission_profiles')) {
        obj['product_permission_profiles'] = ApiClient.convertToType(data['product_permission_profiles'], [ProductPermissionProfileRequest]);
      }
      if (data.hasOwnProperty('ds_groups')) {
        obj['ds_groups'] = ApiClient.convertToType(data['ds_groups'], [DSGroupRequest]);
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
   * @member {Array.<module:model/ProductPermissionProfileRequest>} product_permission_profiles
   */
  exports.prototype['product_permission_profiles'] = undefined;
  /**
   * @member {Array.<module:model/DSGroupRequest>} ds_groups
   */
  exports.prototype['ds_groups'] = undefined;
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


