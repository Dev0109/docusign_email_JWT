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
    define(['ApiClient', 'model/RegionReferenceCount'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./RegionReferenceCount'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.RegionReferenceCountList = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.RegionReferenceCount);
  }
}(this, function(ApiClient, RegionReferenceCount) {
  'use strict';


  /**
   * The RegionReferenceCountList model module.
   * @module model/RegionReferenceCountList
   */

  /**
   * Constructs a new <code>RegionReferenceCountList</code>.
   * @alias module:model/RegionReferenceCountList
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>RegionReferenceCountList</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/RegionReferenceCountList} obj Optional instance to populate.
   * @return {module:model/RegionReferenceCountList} The populated <code>RegionReferenceCountList</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('referenceCounts')) {
        obj['referenceCounts'] = ApiClient.convertToType(data['referenceCounts'], [RegionReferenceCount]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/RegionReferenceCount>} referenceCounts
   */
  exports.prototype['referenceCounts'] = undefined;



  return exports;
}));


