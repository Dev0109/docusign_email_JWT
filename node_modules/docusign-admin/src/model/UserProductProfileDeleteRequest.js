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
    root.DocusignAdmin.UserProductProfileDeleteRequest = factory(root.DocusignAdmin.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The UserProductProfileDeleteRequest model module.
   * @module model/UserProductProfileDeleteRequest
   */

  /**
   * Constructs a new <code>UserProductProfileDeleteRequest</code>.
   * @alias module:model/UserProductProfileDeleteRequest
   * @class
   * @param productIds {Array.<String>} 
   */
  var exports = function(productIds) {
    var _this = this;

    _this['product_ids'] = productIds;
  };

  /**
   * Constructs a <code>UserProductProfileDeleteRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/UserProductProfileDeleteRequest} obj Optional instance to populate.
   * @return {module:model/UserProductProfileDeleteRequest} The populated <code>UserProductProfileDeleteRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('user_email')) {
        obj['user_email'] = ApiClient.convertToType(data['user_email'], 'String');
      }
      if (data.hasOwnProperty('user_id')) {
        obj['user_id'] = ApiClient.convertToType(data['user_id'], 'String');
      }
      if (data.hasOwnProperty('product_ids')) {
        obj['product_ids'] = ApiClient.convertToType(data['product_ids'], ['String']);
      }
    }
    return obj;
  }

  /**
   * @member {String} user_email
   */
  exports.prototype['user_email'] = undefined;
  /**
   * @member {String} user_id
   */
  exports.prototype['user_id'] = undefined;
  /**
   * @member {Array.<String>} product_ids
   */
  exports.prototype['product_ids'] = undefined;



  return exports;
}));


