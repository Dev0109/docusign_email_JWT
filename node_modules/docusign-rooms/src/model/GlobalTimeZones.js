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
    define(['ApiClient', 'model/TimeZone'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./TimeZone'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalTimeZones = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.TimeZone);
  }
}(this, function(ApiClient, TimeZone) {
  'use strict';


  /**
   * The GlobalTimeZones model module.
   * @module model/GlobalTimeZones
   */

  /**
   * Constructs a new <code>GlobalTimeZones</code>.
   * @alias module:model/GlobalTimeZones
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalTimeZones</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalTimeZones} obj Optional instance to populate.
   * @return {module:model/GlobalTimeZones} The populated <code>GlobalTimeZones</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('timeZones')) {
        obj['timeZones'] = ApiClient.convertToType(data['timeZones'], [TimeZone]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/TimeZone>} timeZones
   */
  exports.prototype['timeZones'] = undefined;



  return exports;
}));


