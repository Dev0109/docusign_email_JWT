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
    define(['ApiClient', 'model/TaskDateType'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./TaskDateType'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalTaskDateTypes = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.TaskDateType);
  }
}(this, function(ApiClient, TaskDateType) {
  'use strict';


  /**
   * The GlobalTaskDateTypes model module.
   * @module model/GlobalTaskDateTypes
   */

  /**
   * Constructs a new <code>GlobalTaskDateTypes</code>.
   * @alias module:model/GlobalTaskDateTypes
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalTaskDateTypes</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalTaskDateTypes} obj Optional instance to populate.
   * @return {module:model/GlobalTaskDateTypes} The populated <code>GlobalTaskDateTypes</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('taskDateTypes')) {
        obj['taskDateTypes'] = ApiClient.convertToType(data['taskDateTypes'], [TaskDateType]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/TaskDateType>} taskDateTypes
   */
  exports.prototype['taskDateTypes'] = undefined;



  return exports;
}));


