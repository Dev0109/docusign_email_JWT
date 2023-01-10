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
    define(['ApiClient', 'model/State'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./State'));
  } else {
    // Browser globals (root is window)
    if (!root.DocusignRooms) {
      root.DocusignRooms = {};
    }
    root.DocusignRooms.GlobalStates = factory(root.DocusignRooms.ApiClient, root.DocusignRooms.State);
  }
}(this, function(ApiClient, State) {
  'use strict';


  /**
   * The GlobalStates model module.
   * @module model/GlobalStates
   */

  /**
   * Constructs a new <code>GlobalStates</code>.
   * @alias module:model/GlobalStates
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>GlobalStates</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/GlobalStates} obj Optional instance to populate.
   * @return {module:model/GlobalStates} The populated <code>GlobalStates</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('states')) {
        obj['states'] = ApiClient.convertToType(data['states'], [State]);
      }
    }
    return obj;
  }

  /**
   * @member {Array.<module:model/State>} states
   */
  exports.prototype['states'] = undefined;



  return exports;
}));


