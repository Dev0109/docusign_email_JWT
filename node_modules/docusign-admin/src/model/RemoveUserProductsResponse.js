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
    root.DocusignAdmin.RemoveUserProductsResponse = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The RemoveUserProductsResponse model module.
   * @module model/RemoveUserProductsResponse
   */

  /**
   * Constructs a new <code>RemoveUserProductsResponse</code>.
   * @alias module:model/RemoveUserProductsResponse
   * @class
   * @param isSuccess {Boolean} 
   * @param userProductResults {Object.<String, String>} 
   */
  var exports = function(isSuccess, userProductResults) {
    var _this = this;

    _this['is_success'] = isSuccess;    _this['user_product_results'] = userProductResults;
  };

  /**
   * Constructs a <code>RemoveUserProductsResponse</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/RemoveUserProductsResponse} obj Optional instance to populate.
   * @return {module:model/RemoveUserProductsResponse} The populated <code>RemoveUserProductsResponse</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('is_success')) {
        obj['is_success'] = ApiClient.convertToType(data['is_success'], 'Boolean');
      }
      if (data.hasOwnProperty('user_email')) {
        obj['user_email'] = ApiClient.convertToType(data['user_email'], 'String');
      }
      if (data.hasOwnProperty('user_id')) {
        obj['user_id'] = ApiClient.convertToType(data['user_id'], 'String');
      }
      if (data.hasOwnProperty('user_product_results')) {
        obj['user_product_results'] = ApiClient.convertToType(data['user_product_results'], {'String': 'String'});
      }
    }
    return obj;
  }

  /**
   * @member {Boolean} is_success
   */
  exports.prototype['is_success'] = undefined;
  /**
   * @member {String} user_email
   */
  exports.prototype['user_email'] = undefined;
  /**
   * @member {String} user_id
   */
  exports.prototype['user_id'] = undefined;
  /**
   * @member {Object.<String, String>} user_product_results
   */
  exports.prototype['user_product_results'] = undefined;



  return exports;
}));


