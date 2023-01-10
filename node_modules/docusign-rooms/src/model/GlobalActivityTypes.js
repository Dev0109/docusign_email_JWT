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
    define(['ApiClient', 'model/ActivityType'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./ActivityType'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalActivityTypes = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.ActivityType);
  }
}(this, function(ApiClient, ActivityType) {
  'use strict';


  /**
   * The GlobalActivityTypes model module.
   * @module model/GlobalActivityTypes
   */

  /**
   * Constructs a new <code>GlobalActivityTypes</code>.
   * @alias module:model/GlobalActivityTypes
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalActivityTypes</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalActivityTypes} obj Optional instance to populate.
   * @return {module:model/GlobalActivityTypes} The populated <code>GlobalActivityTypes</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('activityTypes')) {
        obj['activityTypes'] = ApiClient.convertToType(data['activityTypes'], [ActivityType]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/ActivityType>} activityTypes
   */
  exports.prototype['activityTypes'] = undefined;



  return exports;
}));


