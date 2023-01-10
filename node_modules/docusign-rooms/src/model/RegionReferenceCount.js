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
    define(['ApiClient'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.RegionReferenceCount = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The RegionReferenceCount model module.
   * @module model/RegionReferenceCount
   */

  /**
   * Constructs a new <code>RegionReferenceCount</code>.
   * @alias module:model/RegionReferenceCount
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>RegionReferenceCount</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/RegionReferenceCount} obj Optional instance to populate.
   * @return {module:model/RegionReferenceCount} The populated <code>RegionReferenceCount</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('referenceType')) {
        obj['referenceType'] = ApiClient.convertToType(data['referenceType'], 'String');
      }
      if (data.hasOwnProperty('referenceCount')) {
        obj['referenceCount'] = ApiClient.convertToType(data['referenceCount'], 'Number');
      }
    }
    return obj;
  }

  /**
   * @member {String} referenceType
   */
  exports.prototype['referenceType'] = undefined;
  /**
   * @member {Number} referenceCount
   */
  exports.prototype['referenceCount'] = undefined;



  return exports;
}));


