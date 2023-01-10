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
    root.DocusignRooms.RoomUserSortingOption = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';

  /**
   * Enum class RoomUserSortingOption.
   * @enum {}
   * @readonly
   */
  var exports = {
    /**
     * value: "FirstNameAsc"
     * @const
     */
    "firstNameAsc": "FirstNameAsc",
    /**
     * value: "LastNameAsc"
     * @const
     */
    "lastNameAsc": "LastNameAsc",
    /**
     * value: "EmailAsc"
     * @const
     */
    "emailAsc": "EmailAsc",
    /**
     * value: "FirstNameDesc"
     * @const
     */
    "firstNameDesc": "FirstNameDesc",
    /**
     * value: "LastNameDesc"
     * @const
     */
    "lastNameDesc": "LastNameDesc",
    /**
     * value: "EmailDesc"
     * @const
     */
    "emailDesc": "EmailDesc"  };

  /**
   * Returns a <code>RoomUserSortingOption</code> enum value from a Javascript object name.
   * @param {Object} data The plain JavaScript object containing the name of the enum value.
   * @return {module:model/RoomUserSortingOption} The enum <code>RoomUserSortingOption</code> value.
   */
  exports.constructFromObject = function(object) {
    return object;
  };

  return exports;
}));


