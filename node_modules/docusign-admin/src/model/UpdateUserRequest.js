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
    define(['ApiClient', 'model/UpdateMembershipRequest'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./UpdateMembershipRequest'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.UpdateUserRequest = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.UpdateMembershipRequest);
  }
}(this, function(ApiClient, UpdateMembershipRequest) {
  'use strict';


  /**
   * The UpdateUserRequest model module.
   * @module model/UpdateUserRequest
   */

  /**
   * Constructs a new <code>UpdateUserRequest</code>.
   * @alias module:model/UpdateUserRequest
   * @class
   * @param id {String} 
   * @param siteId {Number} 
   */
  var exports = function(id, siteId) {
    var _this = this;

    _this['id'] = id;    _this['site_id'] = siteId;
  };

  /**
   * Constructs a <code>UpdateUserRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UpdateUserRequest} obj Optional instance to populate.
   * @return {module:model/UpdateUserRequest} The populated <code>UpdateUserRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
      }
      if (data.hasOwnProperty('site_id')) {
        obj['site_id'] = ApiClient.convertToType(data['site_id'], 'Number');
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
      if (data.hasOwnProperty('federated_status')) {
        obj['federated_status'] = ApiClient.convertToType(data['federated_status'], 'String');
      }
      if (data.hasOwnProperty('force_password_change')) {
        obj['force_password_change'] = ApiClient.convertToType(data['force_password_change'], 'Boolean');
      }
      if (data.hasOwnProperty('memberships')) {
        obj['memberships'] = ApiClient.convertToType(data['memberships'], [UpdateMembershipRequest]);
      }
      if (data.hasOwnProperty('device_verification_enabled')) {
        obj['device_verification_enabled'] = ApiClient.convertToType(data['device_verification_enabled'], 'Boolean');
      }
    }
    return obj;
  }

  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
  /**
   * @member {Number} site_id
   */
  exports.prototype['site_id'] = undefined;
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
   * @member {String} federated_status
   */
  exports.prototype['federated_status'] = undefined;
  /**
   * @member {Boolean} force_password_change
   */
  exports.prototype['force_password_change'] = undefined;
  /**
   * @member {Array.<module:model/UpdateMembershipRequest>} memberships
   */
  exports.prototype['memberships'] = undefined;
  /**
   * @member {Boolean} device_verification_enabled
   */
  exports.prototype['device_verification_enabled'] = undefined;



  return exports;
}));


