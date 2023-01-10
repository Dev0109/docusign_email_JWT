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
    define(['ApiClient', 'model/DSGroupResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./DSGroupResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.OrganizationUserResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DSGroupResponse);
  }
}(this, function(ApiClient, DSGroupResponse) {
  'use strict';


  /**
   * The OrganizationUserResponse model module.
   * @module model/OrganizationUserResponse
   */

  /**
   * Constructs a new <code>OrganizationUserResponse</code>.
   * @alias module:model/OrganizationUserResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OrganizationUserResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OrganizationUserResponse} obj Optional instance to populate.
   * @return {module:model/OrganizationUserResponse} The populated <code>OrganizationUserResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('id')) {
        obj['id'] = ApiClient.convertToType(data['id'], 'String');
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
      if (data.hasOwnProperty('user_status')) {
        obj['user_status'] = ApiClient.convertToType(data['user_status'], 'String');
      }
      if (data.hasOwnProperty('membership_status')) {
        obj['membership_status'] = ApiClient.convertToType(data['membership_status'], 'String');
      }
      if (data.hasOwnProperty('email')) {
        obj['email'] = ApiClient.convertToType(data['email'], 'String');
      }
      if (data.hasOwnProperty('created_on')) {
        obj['created_on'] = ApiClient.convertToType(data['created_on'], 'Date');
      }
      if (data.hasOwnProperty('membership_created_on')) {
        obj['membership_created_on'] = ApiClient.convertToType(data['membership_created_on'], 'Date');
      }
      if (data.hasOwnProperty('ds_groups')) {
        obj['ds_groups'] = ApiClient.convertToType(data['ds_groups'], [DSGroupResponse]);
      }
      if (data.hasOwnProperty('membership_id')) {
        obj['membership_id'] = ApiClient.convertToType(data['membership_id'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} id
   */
  exports.prototype['id'] = undefined;
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
   * @member {String} user_status
   */
  exports.prototype['user_status'] = undefined;
  /**
   * @member {String} membership_status
   */
  exports.prototype['membership_status'] = undefined;
  /**
   * @member {String} email
   */
  exports.prototype['email'] = undefined;
  /**
   * @member {Date} created_on
   */
  exports.prototype['created_on'] = undefined;
  /**
   * @member {Date} membership_created_on
   */
  exports.prototype['membership_created_on'] = undefined;
  /**
   * @member {Array.<module:model/DSGroupResponse>} ds_groups
   */
  exports.prototype['ds_groups'] = undefined;
  /**
   * @member {String} membership_id
   */
  exports.prototype['membership_id'] = undefined;



  return exports;
}));


