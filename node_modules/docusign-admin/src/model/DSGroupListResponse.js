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
    root.DocusignAdmin.DSGroupListResponse = factory(root.DocusignAdmin.ApiClient, root.DocusignAdmin.DSGroupResponse);
  }
}(this, function(ApiClient, DSGroupResponse) {
  'use strict';


  /**
   * The DSGroupListResponse model module.
   * @module model/DSGroupListResponse
   */

  /**
   * Constructs a new <code>DSGroupListResponse</code>.
   * @alias module:model/DSGroupListResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>DSGroupListResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/DSGroupListResponse} obj Optional instance to populate.
   * @return {module:model/DSGroupListResponse} The populated <code>DSGroupListResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('page')) {
        obj['page'] = ApiClient.convertToType(data['page'], 'Number');
      }
      if (data.hasOwnProperty('page_size')) {
        obj['page_size'] = ApiClient.convertToType(data['page_size'], 'Number');
      }
      if (data.hasOwnProperty('total_count')) {
        obj['total_count'] = ApiClient.convertToType(data['total_count'], 'Number');
      }
      if (data.hasOwnProperty('account_id')) {
        obj['account_id'] = ApiClient.convertToType(data['account_id'], 'String');
      }
      if (data.hasOwnProperty('ds_groups')) {
        obj['ds_groups'] = ApiClient.convertToType(data['ds_groups'], [DSGroupResponse]);
      }
    }
    return obj;
  }

  /**
   * @member {Number} page
   */
  exports.prototype['page'] = undefined;
  /**
   * @member {Number} page_size
   */
  exports.prototype['page_size'] = undefined;
  /**
   * @member {Number} total_count
   */
  exports.prototype['total_count'] = undefined;
  /**
   * @member {String} account_id
   */
  exports.prototype['account_id'] = undefined;
  /**
   * @member {Array.<module:model/DSGroupResponse>} ds_groups
   */
  exports.prototype['ds_groups'] = undefined;



  return exports;
}));


