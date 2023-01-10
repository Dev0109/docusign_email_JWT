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
    root.DocusignAdmin.RequiredAttributeMappingResponse = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The RequiredAttributeMappingResponse model module.
   * @module model/RequiredAttributeMappingResponse
   */

  /**
   * Constructs a new <code>RequiredAttributeMappingResponse</code>.
   * @alias module:model/RequiredAttributeMappingResponse
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>RequiredAttributeMappingResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/RequiredAttributeMappingResponse} obj Optional instance to populate.
   * @return {module:model/RequiredAttributeMappingResponse} The populated <code>RequiredAttributeMappingResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('required_attribute_id')) {
        obj['required_attribute_id'] = ApiClient.convertToType(data['required_attribute_id'], 'Number');
      }
      if (data.hasOwnProperty('required_attribute_name')) {
        obj['required_attribute_name'] = ApiClient.convertToType(data['required_attribute_name'], 'String');
      }
      if (data.hasOwnProperty('required_attribute_friendly_name')) {
        obj['required_attribute_friendly_name'] = ApiClient.convertToType(data['required_attribute_friendly_name'], 'String');
      }
      if (data.hasOwnProperty('substitute_attribute_name')) {
        obj['substitute_attribute_name'] = ApiClient.convertToType(data['substitute_attribute_name'], 'String');
      }
    }
    return obj;
  }

  /**
   * @member {Number} required_attribute_id
   */
  exports.prototype['required_attribute_id'] = undefined;
  /**
   * @member {String} required_attribute_name
   */
  exports.prototype['required_attribute_name'] = undefined;
  /**
   * @member {String} required_attribute_friendly_name
   */
  exports.prototype['required_attribute_friendly_name'] = undefined;
  /**
   * @member {String} substitute_attribute_name
   */
  exports.prototype['substitute_attribute_name'] = undefined;



  return exports;
}));


