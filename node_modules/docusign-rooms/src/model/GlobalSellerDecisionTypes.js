/**
 * DocuSign Rooms API - v2
 * An API for an integrator to access the features of DocuSign Rooms
 *
 * OpenAPI spec version: v2
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/SellerDecisionType'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./SellerDecisionType'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalSellerDecisionTypes = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.SellerDecisionType);
  }
}(this, function(ApiClient, SellerDecisionType) {
  'use strict';


  /**
   * The GlobalSellerDecisionTypes model module.
   * @module model/GlobalSellerDecisionTypes
   */

  /**
   * Constructs a new <code>GlobalSellerDecisionTypes</code>.
   * @alias module:model/GlobalSellerDecisionTypes
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalSellerDecisionTypes</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalSellerDecisionTypes} obj Optional instance to populate.
   * @return {module:model/GlobalSellerDecisionTypes} The populated <code>GlobalSellerDecisionTypes</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('sellerDecisionTypes')) {
        obj['sellerDecisionTypes'] = ApiClient.convertToType(data['sellerDecisionTypes'], [SellerDecisionType]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/SellerDecisionType>} sellerDecisionTypes
   */
  exports.prototype['sellerDecisionTypes'] = undefined;



  return exports;
}));


