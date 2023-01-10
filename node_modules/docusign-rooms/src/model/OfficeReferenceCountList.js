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
    define(['ApiClient', 'model/OfficeReferenceCount'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./OfficeReferenceCount'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.OfficeReferenceCountList = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.OfficeReferenceCount);
  }
}(this, function(ApiClient, OfficeReferenceCount) {
  'use strict';


  /**
   * The OfficeReferenceCountList model module.
   * @module model/OfficeReferenceCountList
   */

  /**
   * Constructs a new <code>OfficeReferenceCountList</code>.
   * @alias module:model/OfficeReferenceCountList
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>OfficeReferenceCountList</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/OfficeReferenceCountList} obj Optional instance to populate.
   * @return {module:model/OfficeReferenceCountList} The populated <code>OfficeReferenceCountList</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('referencesCounts')) {
        obj['referencesCounts'] = ApiClient.convertToType(data['referencesCounts'], [OfficeReferenceCount]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/OfficeReferenceCount>} referencesCounts
   */
  exports.prototype['referencesCounts'] = undefined;



  return exports;
}));


