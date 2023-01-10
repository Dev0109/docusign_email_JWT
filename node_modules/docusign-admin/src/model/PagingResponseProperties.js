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
    root.DocusignAdmin.PagingResponseProperties = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The PagingResponseProperties model module.
   * @module model/PagingResponseProperties
   */

  /**
   * Constructs a new <code>PagingResponseProperties</code>.
   * @alias module:model/PagingResponseProperties
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>PagingResponseProperties</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/PagingResponseProperties} obj Optional instance to populate.
   * @return {module:model/PagingResponseProperties} The populated <code>PagingResponseProperties</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('result_set_size')) {
        obj['result_set_size'] = ApiClient.convertToType(data['result_set_size'], 'Number');
      }
      if (data.hasOwnProperty('result_set_start_position')) {
        obj['result_set_start_position'] = ApiClient.convertToType(data['result_set_start_position'], 'Number');
      }
      if (data.hasOwnProperty('result_set_end_position')) {
        obj['result_set_end_position'] = ApiClient.convertToType(data['result_set_end_position'], 'Number');
      }
      if (data.hasOwnProperty('total_set_size')) {
        obj['total_set_size'] = ApiClient.convertToType(data['total_set_size'], 'Number');
      }
      if (data.hasOwnProperty('next')) {
        obj['next'] = ApiClient.convertToType(data['next'], 'String');
      }
      if (data.hasOwnProperty('previous')) {
        obj['previous'] = ApiClient.convertToType(data['previous'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {Number} result_set_size
   */
  exports.prototype['result_set_size'] = undefined;
  /**
   * @member {Number} result_set_start_position
   */
  exports.prototype['result_set_start_position'] = undefined;
  /**
   * @member {Number} result_set_end_position
   */
  exports.prototype['result_set_end_position'] = undefined;
  /**
   * @member {Number} total_set_size
   */
  exports.prototype['total_set_size'] = undefined;
  /**
   * @member {String} next
   */
  exports.prototype['next'] = undefined;
  /**
   * @member {String} previous
   */
  exports.prototype['previous'] = undefined;



  return exports;
}));


