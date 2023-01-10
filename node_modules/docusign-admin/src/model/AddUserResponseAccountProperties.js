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
    define(['ApiClient', 'model/DSGroupResponse', 'model/ProductPermissionProfileResponse'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./DSGroupResponse'), require('./ProductPermissionProfileResponse'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignAdmin) {
      root.DocusignAdmin = {};
    }
    root.DocusignAdmin.AddUserResponseAccountProperties = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DSGroupResponse, root.DocusignAdmin.ProductPermissionProfileResponse);
  }
}(this, function(ApiClient, DSGroupResponse, ProductPermissionProfileResponse) {
  'use strict';


  /**
   * The AddUserResponseAccountProperties model module.
   * @module model/AddUserResponseAccountProperties
   */

  /**
   * Constructs a new <code>AddUserResponseAccountProperties</code>.
   * @alias module:model/AddUserResponseAccountProperties
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>AddUserResponseAccountProperties</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/AddUserResponseAccountProperties} obj Optional instance to populate.
   * @return {module:model/AddUserResponseAccountProperties} The populated <code>AddUserResponseAccountProperties</code> instance.
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
      if (data.hasOwnProperty('product_permission_profiles')) {
        obj['product_permission_profiles'] = ApiClient.convertToType(data['product_permission_profiles'], [ProductPermissionProfileResponse]);
      }
      if (data.hasOwnProperty('ds_groups')) {
        obj['ds_groups'] = ApiClient.convertToType(data['ds_groups'], [DSGroupResponse]);
      }
      if (data.hasOwnProperty('company_name')) {
        obj['company_name'] = ApiClient.convertToType(data['company_name'], 'String');
      }
      if (data.hasOwnProperty('job_title')) {
        obj['job_title'] = ApiClient.convertToType(data['job_title'], 'String');
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
   * @member {Array.<module:model/ProductPermissionProfileResponse>} product_permission_profiles
   */
  exports.prototype['product_permission_profiles'] = undefined;
  /**
   * @member {Array.<module:model/DSGroupResponse>} ds_groups
   */
  exports.prototype['ds_groups'] = undefined;
  /**
   * @member {String} company_name
   */
  exports.prototype['company_name'] = undefined;
  /**
   * @member {String} job_title
   */
  exports.prototype['job_title'] = undefined;



  return exports;
}));


