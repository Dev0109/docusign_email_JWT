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
    root.DocusignRooms.TaskListTemplate = factory(root.DocusignRooms.ApiClient);
  }
}(this, function(ApiClient) {
  'use strict';


  /**
   * The TaskListTemplate model module.
   * @module model/TaskListTemplate
   */

  /**
   * Constructs a new <code>TaskListTemplate</code>.
   * @alias module:model/TaskListTemplate
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>TaskListTemplate</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/TaskListTemplate} obj Optional instance to populate.
   * @return {module:model/TaskListTemplate} The populated <code>TaskListTemplate</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('taskListTemplateId')) {
        obj['taskListTemplateId'] = ApiClient.convertToType(data['taskListTemplateId'], 'Number');
      }
      if (data.hasOwnProperty('name')) {
        obj['name'] = ApiClient.convertToType(data['name'], 'String');
      }
      if (data.hasOwnProperty('taskCount')) {
        obj['taskCount'] = ApiClient.convertToType(data['taskCount'], 'Number');
      }
      if (data.hasOwnProperty('tasksWithDocumentsCount')) {
        obj['tasksWithDocumentsCount'] = ApiClient.convertToType(data['tasksWithDocumentsCount'], 'Number');
      }
    }
    return obj;
  }

  /**
   * @member {Number} taskListTemplateId
   */
  exports.prototype['taskListTemplateId'] = undefined;
  /**
   * @member {String} name
   */
  exports.prototype['name'] = undefined;
  /**
   * @member {Number} taskCount
   */
  exports.prototype['taskCount'] = undefined;
  /**
   * @member {Number} tasksWithDocumentsCount
   */
  exports.prototype['tasksWithDocumentsCount'] = undefined;



  return exports;
}));


