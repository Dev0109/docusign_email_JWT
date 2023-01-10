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
    root.DocusignAdmin.DSGroupResponse = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The DSGroupResponse model module.
   * @module model/DSGroupResponse
   */

  /**
   * Constructs a new <code>DSGroupResponse</code>.
   * @alias module:model/DSGroupResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>DSGroupResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DSGroupResponse} obj Optional instance to populate.
   * @return {module:model/DSGroupResponse} The populated <code>DSGroupResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('ds_group_id')) {
        obj['ds_group_id'] = ApiClient.convertToType(data['ds_group_id'], 'String');
      }
      if (data.hasOwnProperty('account_id')) {
        obj['account_id'] = ApiClient.convertToType(data['account_id'], 'String');
      }
      if (data.hasOwnProperty('source_product_name')) {
        obj['source_product_name'] = ApiClient.convertToType(data['source_product_name'], 'String');
      }
      if (data.hasOwnProperty('group_id')) {
        obj['group_id'] = ApiClient.convertToType(data['group_id'], 'String');
      }
      if (data.hasOwnProperty('group_name')) {
        obj['group_name'] = ApiClient.convertToType(data['group_name'], 'String');
      }
      if (data.hasOwnProperty('description')) {
        obj['description'] = ApiClient.convertToType(data['description'], 'String');
      }
      if (data.hasOwnProperty('is_admin')) {
        obj['is_admin'] = ApiClient.convertToType(data['is_admin'], 'Boolean');
      }
      if (data.hasOwnProperty('last_modified_on')) {
        obj['last_modified_on'] = ApiClient.convertToType(data['last_modified_on'], 'Date');
      }
      if (data.hasOwnProperty('user_count')) {
        obj['user_count'] = ApiClient.convertToType(data['user_count'], 'Number');
      }
      if (data.hasOwnProperty('external_account_id')) {
        obj['external_account_id'] = ApiClient.convertToType(data['external_account_id'], 'Number');
      }
      if (data.hasOwnProperty('account_name')) {
        obj['account_name'] = ApiClient.convertToType(data['account_name'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {String} ds_group_id
   */
  exports.prototype['ds_group_id'] = undefined;
  /**
   * @member {String} account_id
   */
  exports.prototype['account_id'] = undefined;
  /**
   * @member {String} source_product_name
   */
  exports.prototype['source_product_name'] = undefined;
  /**
   * @member {String} group_id
   */
  exports.prototype['group_id'] = undefined;
  /**
   * @member {String} group_name
   */
  exports.prototype['group_name'] = undefined;
  /**
   * @member {String} description
   */
  exports.prototype['description'] = undefined;
  /**
   * @member {Boolean} is_admin
   */
  exports.prototype['is_admin'] = undefined;
  /**
   * @member {Date} last_modified_on
   */
  exports.prototype['last_modified_on'] = undefined;
  /**
   * @member {Number} user_count
   */
  exports.prototype['user_count'] = undefined;
  /**
   * @member {Number} external_account_id
   */
  exports.prototype['external_account_id'] = undefined;
  /**
   * @member {String} account_name
   */
  exports.prototype['account_name'] = undefined;



  return exports;
}));


