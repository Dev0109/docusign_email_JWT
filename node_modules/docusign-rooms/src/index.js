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
(function(factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['Configuration', 'ApiClient', 'model/AccessLevel', 'model/AccountStatus', 'model/AccountSummary', 'model/ActivityType', 'model/ApiError', 'model/AssignableRoles', 'model/ClassicAdminToInvite', 'model/ClassicAgentToInvite', 'model/ClassicManagerPermissions', 'model/ClassicManagerToInvite', 'model/ClosingStatus', 'model/ContactSide', 'model/Country', 'model/Currency', 'model/CustomData', 'model/DependsOn', 'model/DesignatedOffice', 'model/DesignatedRegion', 'model/Document', 'model/DocumentUser', 'model/DocumentUserForCreate', 'model/ESignAccountRoleSettings', 'model/ESignPermissionProfile', 'model/ESignPermissionProfileList', 'model/ExternalFormFillSession', 'model/ExternalFormFillSessionForCreate', 'model/Field', 'model/FieldConfiguration', 'model/FieldData', 'model/FieldDataForCreate', 'model/FieldDataForUpdate', 'model/FieldSet', 'model/FieldsCustomDataFilterType', 'model/FinancingType', 'model/FormDetails', 'model/FormForAdd', 'model/FormGroup', 'model/FormGroupForCreate', 'model/FormGroupForUpdate', 'model/FormGroupFormToAssign', 'model/FormGroupSummary', 'model/FormGroupSummaryList', 'model/FormLibrarySummary', 'model/FormLibrarySummaryList', 'model/FormSummary', 'model/FormSummaryList', 'model/GlobalActivityTypes', 'model/GlobalClosingStatuses', 'model/GlobalContactSides', 'model/GlobalCountries', 'model/GlobalCurrencies', 'model/GlobalFinancingTypes', 'model/GlobalOriginsOfLeads', 'model/GlobalPropertyTypes', 'model/GlobalRoomContactTypes', 'model/GlobalSellerDecisionTypes', 'model/GlobalSpecialCircumstanceTypes', 'model/GlobalStates', 'model/GlobalTaskDateTypes', 'model/GlobalTaskResponsibilityTypes', 'model/GlobalTaskStatuses', 'model/GlobalTimeZones', 'model/GlobalTransactionSides', 'model/GroupForm', 'model/LockedOutDetails', 'model/MemberSortingOption', 'model/Office', 'model/OfficeForCreate', 'model/OfficeReferenceCount', 'model/OfficeReferenceCountList', 'model/OfficeSummary', 'model/OfficeSummaryList', 'model/OriginOfLead', 'model/Permissions', 'model/ProductVersion', 'model/PropertyType', 'model/Region', 'model/RegionReferenceCount', 'model/RegionReferenceCountList', 'model/RegionSummary', 'model/RegionSummaryList', 'model/Role', 'model/RoleForCreate', 'model/RoleForUpdate', 'model/RoleSummary', 'model/RoleSummaryList', 'model/Room', 'model/RoomContactType', 'model/RoomDocument', 'model/RoomDocumentList', 'model/RoomDocumentOwner', 'model/RoomFolder', 'model/RoomFolderList', 'model/RoomForCreate', 'model/RoomInvite', 'model/RoomInviteResponse', 'model/RoomPicture', 'model/RoomStatus', 'model/RoomSummary', 'model/RoomSummaryList', 'model/RoomTemplate', 'model/RoomTemplatesSummaryList', 'model/RoomUser', 'model/RoomUserForUpdate', 'model/RoomUserRemovalDetail', 'model/RoomUserSortingOption', 'model/RoomUserSummary', 'model/RoomUsersResult', 'model/SelectListFieldOption', 'model/SellerDecisionType', 'model/SpecialCircumstanceType', 'model/State', 'model/TaskDateType', 'model/TaskList', 'model/TaskListForCreate', 'model/TaskListSummary', 'model/TaskListSummaryList', 'model/TaskListTemplate', 'model/TaskListTemplateList', 'model/TaskResponsibilityType', 'model/TaskStatus', 'model/TaskSummary', 'model/TimeZone', 'model/TransactionSide', 'model/User', 'model/UserForUpdate', 'model/UserSummary', 'model/UserSummaryList', 'model/UserToInvite', 'api/AccountsApi', 'api/ActivityTypesApi', 'api/ClosingStatusesApi', 'api/ContactSidesApi', 'api/CountriesApi', 'api/CurrenciesApi', 'api/DocumentsApi', 'api/ESignPermissionProfilesApi', 'api/ExternalFormFillSessionsApi', 'api/FieldsApi', 'api/FinancingTypesApi', 'api/FormDetailsApi', 'api/FormGroupsApi', 'api/FormLibrariesApi', 'api/OfficesApi', 'api/OriginsOfLeadsApi', 'api/PropertyTypesApi', 'api/RegionsApi', 'api/RolesApi', 'api/RoomContactTypesApi', 'api/RoomFoldersApi', 'api/RoomTemplatesApi', 'api/RoomsApi', 'api/SellerDecisionTypesApi', 'api/SpecialCircumstanceTypesApi', 'api/StatesApi', 'api/TaskDateTypesApi', 'api/TaskListTemplatesApi', 'api/TaskListsApi', 'api/TaskResponsibilityTypesApi', 'api/TaskStatusesApi', 'api/TimeZonesApi', 'api/TransactionSidesApi', 'api/UsersApi'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('./Configuration'), require('./ApiClient'), require('./model/AccessLevel'), require('./model/AccountStatus'), require('./model/AccountSummary'), require('./model/ActivityType'), require('./model/ApiError'), require('./model/AssignableRoles'), require('./model/ClassicAdminToInvite'), require('./model/ClassicAgentToInvite'), require('./model/ClassicManagerPermissions'), require('./model/ClassicManagerToInvite'), require('./model/ClosingStatus'), require('./model/ContactSide'), require('./model/Country'), require('./model/Currency'), require('./model/CustomData'), require('./model/DependsOn'), require('./model/DesignatedOffice'), require('./model/DesignatedRegion'), require('./model/Document'), require('./model/DocumentUser'), require('./model/DocumentUserForCreate'), require('./model/ESignAccountRoleSettings'), require('./model/ESignPermissionProfile'), require('./model/ESignPermissionProfileList'), require('./model/ExternalFormFillSession'), require('./model/ExternalFormFillSessionForCreate'), require('./model/Field'), require('./model/FieldConfiguration'), require('./model/FieldData'), require('./model/FieldDataForCreate'), require('./model/FieldDataForUpdate'), require('./model/FieldSet'), require('./model/FieldsCustomDataFilterType'), require('./model/FinancingType'), require('./model/FormDetails'), require('./model/FormForAdd'), require('./model/FormGroup'), require('./model/FormGroupForCreate'), require('./model/FormGroupForUpdate'), require('./model/FormGroupFormToAssign'), require('./model/FormGroupSummary'), require('./model/FormGroupSummaryList'), require('./model/FormLibrarySummary'), require('./model/FormLibrarySummaryList'), require('./model/FormSummary'), require('./model/FormSummaryList'), require('./model/GlobalActivityTypes'), require('./model/GlobalClosingStatuses'), require('./model/GlobalContactSides'), require('./model/GlobalCountries'), require('./model/GlobalCurrencies'), require('./model/GlobalFinancingTypes'), require('./model/GlobalOriginsOfLeads'), require('./model/GlobalPropertyTypes'), require('./model/GlobalRoomContactTypes'), require('./model/GlobalSellerDecisionTypes'), require('./model/GlobalSpecialCircumstanceTypes'), require('./model/GlobalStates'), require('./model/GlobalTaskDateTypes'), require('./model/GlobalTaskResponsibilityTypes'), require('./model/GlobalTaskStatuses'), require('./model/GlobalTimeZones'), require('./model/GlobalTransactionSides'), require('./model/GroupForm'), require('./model/LockedOutDetails'), require('./model/MemberSortingOption'), require('./model/Office'), require('./model/OfficeForCreate'), require('./model/OfficeReferenceCount'), require('./model/OfficeReferenceCountList'), require('./model/OfficeSummary'), require('./model/OfficeSummaryList'), require('./model/OriginOfLead'), require('./model/Permissions'), require('./model/ProductVersion'), require('./model/PropertyType'), require('./model/Region'), require('./model/RegionReferenceCount'), require('./model/RegionReferenceCountList'), require('./model/RegionSummary'), require('./model/RegionSummaryList'), require('./model/Role'), require('./model/RoleForCreate'), require('./model/RoleForUpdate'), require('./model/RoleSummary'), require('./model/RoleSummaryList'), require('./model/Room'), require('./model/RoomContactType'), require('./model/RoomDocument'), require('./model/RoomDocumentList'), require('./model/RoomDocumentOwner'), require('./model/RoomFolder'), require('./model/RoomFolderList'), require('./model/RoomForCreate'), require('./model/RoomInvite'), require('./model/RoomInviteResponse'), require('./model/RoomPicture'), require('./model/RoomStatus'), require('./model/RoomSummary'), require('./model/RoomSummaryList'), require('./model/RoomTemplate'), require('./model/RoomTemplatesSummaryList'), require('./model/RoomUser'), require('./model/RoomUserForUpdate'), require('./model/RoomUserRemovalDetail'), require('./model/RoomUserSortingOption'), require('./model/RoomUserSummary'), require('./model/RoomUsersResult'), require('./model/SelectListFieldOption'), require('./model/SellerDecisionType'), require('./model/SpecialCircumstanceType'), require('./model/State'), require('./model/TaskDateType'), require('./model/TaskList'), require('./model/TaskListForCreate'), require('./model/TaskListSummary'), require('./model/TaskListSummaryList'), require('./model/TaskListTemplate'), require('./model/TaskListTemplateList'), require('./model/TaskResponsibilityType'), require('./model/TaskStatus'), require('./model/TaskSummary'), require('./model/TimeZone'), require('./model/TransactionSide'), require('./model/User'), require('./model/UserForUpdate'), require('./model/UserSummary'), require('./model/UserSummaryList'), require('./model/UserToInvite'), require('./api/AccountsApi'), require('./api/ActivityTypesApi'), require('./api/ClosingStatusesApi'), require('./api/ContactSidesApi'), require('./api/CountriesApi'), require('./api/CurrenciesApi'), require('./api/DocumentsApi'), require('./api/ESignPermissionProfilesApi'), require('./api/ExternalFormFillSessionsApi'), require('./api/FieldsApi'), require('./api/FinancingTypesApi'), require('./api/FormDetailsApi'), require('./api/FormGroupsApi'), require('./api/FormLibrariesApi'), require('./api/OfficesApi'), require('./api/OriginsOfLeadsApi'), require('./api/PropertyTypesApi'), require('./api/RegionsApi'), require('./api/RolesApi'), require('./api/RoomContactTypesApi'), require('./api/RoomFoldersApi'), require('./api/RoomTemplatesApi'), require('./api/RoomsApi'), require('./api/SellerDecisionTypesApi'), require('./api/SpecialCircumstanceTypesApi'), require('./api/StatesApi'), require('./api/TaskDateTypesApi'), require('./api/TaskListTemplatesApi'), require('./api/TaskListsApi'), require('./api/TaskResponsibilityTypesApi'), require('./api/TaskStatusesApi'), require('./api/TimeZonesApi'), require('./api/TransactionSidesApi'), require('./api/UsersApi'));
  }
}(function(Configuration, ApiClient, AccessLevel, AccountStatus, AccountSummary, ActivityType, ApiError, AssignableRoles, ClassicAdminToInvite, ClassicAgentToInvite, ClassicManagerPermissions, ClassicManagerToInvite, ClosingStatus, ContactSide, Country, Currency, CustomData, DependsOn, DesignatedOffice, DesignatedRegion, Document, DocumentUser, DocumentUserForCreate, ESignAccountRoleSettings, ESignPermissionProfile, ESignPermissionProfileList, ExternalFormFillSession, ExternalFormFillSessionForCreate, Field, FieldConfiguration, FieldData, FieldDataForCreate, FieldDataForUpdate, FieldSet, FieldsCustomDataFilterType, FinancingType, FormDetails, FormForAdd, FormGroup, FormGroupForCreate, FormGroupForUpdate, FormGroupFormToAssign, FormGroupSummary, FormGroupSummaryList, FormLibrarySummary, FormLibrarySummaryList, FormSummary, FormSummaryList, GlobalActivityTypes, GlobalClosingStatuses, GlobalContactSides, GlobalCountries, GlobalCurrencies, GlobalFinancingTypes, GlobalOriginsOfLeads, GlobalPropertyTypes, GlobalRoomContactTypes, GlobalSellerDecisionTypes, GlobalSpecialCircumstanceTypes, GlobalStates, GlobalTaskDateTypes, GlobalTaskResponsibilityTypes, GlobalTaskStatuses, GlobalTimeZones, GlobalTransactionSides, GroupForm, LockedOutDetails, MemberSortingOption, Office, OfficeForCreate, OfficeReferenceCount, OfficeReferenceCountList, OfficeSummary, OfficeSummaryList, OriginOfLead, Permissions, ProductVersion, PropertyType, Region, RegionReferenceCount, RegionReferenceCountList, RegionSummary, RegionSummaryList, Role, RoleForCreate, RoleForUpdate, RoleSummary, RoleSummaryList, Room, RoomContactType, RoomDocument, RoomDocumentList, RoomDocumentOwner, RoomFolder, RoomFolderList, RoomForCreate, RoomInvite, RoomInviteResponse, RoomPicture, RoomStatus, RoomSummary, RoomSummaryList, RoomTemplate, RoomTemplatesSummaryList, RoomUser, RoomUserForUpdate, RoomUserRemovalDetail, RoomUserSortingOption, RoomUserSummary, RoomUsersResult, SelectListFieldOption, SellerDecisionType, SpecialCircumstanceType, State, TaskDateType, TaskList, TaskListForCreate, TaskListSummary, TaskListSummaryList, TaskListTemplate, TaskListTemplateList, TaskResponsibilityType, TaskStatus, TaskSummary, TimeZone, TransactionSide, User, UserForUpdate, UserSummary, UserSummaryList, UserToInvite, AccountsApi, ActivityTypesApi, ClosingStatusesApi, ContactSidesApi, CountriesApi, CurrenciesApi, DocumentsApi, ESignPermissionProfilesApi, ExternalFormFillSessionsApi, FieldsApi, FinancingTypesApi, FormDetailsApi, FormGroupsApi, FormLibrariesApi, OfficesApi, OriginsOfLeadsApi, PropertyTypesApi, RegionsApi, RolesApi, RoomContactTypesApi, RoomFoldersApi, RoomTemplatesApi, RoomsApi, SellerDecisionTypesApi, SpecialCircumstanceTypesApi, StatesApi, TaskDateTypesApi, TaskListTemplatesApi, TaskListsApi, TaskResponsibilityTypesApi, TaskStatusesApi, TimeZonesApi, TransactionSidesApi, UsersApi) {
  'use strict';

  /**
   * DocuSign Node.js API client..<br>
   * The <code>index</code> module provides access to constructors for all the classes which comprise the public API.
   * <p>
   * An AMD (recommended!) or CommonJS application will generally do something equivalent to the following:
   * <pre>
   * var DocusignRooms = require('index'); // See note below*.
   * var xxxSvc = new DocusignRooms.XxxApi(); // Allocate the API class we're going to use.
   * var yyyModel = new DocusignRooms.Yyy(); // Construct a model instance.
   * yyyModel.someProperty = 'someValue';
   * ...
   * var zzz = xxxSvc.doSomething(yyyModel); // Invoke the service.
   * ...
   * </pre>
   * <em>*NOTE: For a top-level AMD script, use require(['index'], function(){...})
   * and put the application logic within the callback function.</em>
   * </p>
   * <p>
   * A non-AMD browser application (discouraged) might do something like this:
   * <pre>
   * var xxxSvc = new DocusignRooms.XxxApi(); // Allocate the API class we're going to use.
   * var yyy = new DocusignRooms.Yyy(); // Construct a model instance.
   * yyyModel.someProperty = 'someValue';
   * ...
   * var zzz = xxxSvc.doSomething(yyyModel); // Invoke the service.
   * ...
   * </pre>
   * </p>
   * @module index
   */
  var exports = {
	/**
	 * The configuration constructor.
	 * @property {module:Configuration}
	 */
	 Configuration: Configuration,
	/**
     * The ApiClient constructor.
     * @property {module:ApiClient}
     */
    ApiClient: ApiClient,
    /**
     * The AccessLevel model constructor.
     * @property {module:model/AccessLevel}
     */
    AccessLevel: AccessLevel,
    /**
     * The AccountStatus model constructor.
     * @property {module:model/AccountStatus}
     */
    AccountStatus: AccountStatus,
    /**
     * The AccountSummary model constructor.
     * @property {module:model/AccountSummary}
     */
    AccountSummary: AccountSummary,
    /**
     * The ActivityType model constructor.
     * @property {module:model/ActivityType}
     */
    ActivityType: ActivityType,
    /**
     * The ApiError model constructor.
     * @property {module:model/ApiError}
     */
    ApiError: ApiError,
    /**
     * The AssignableRoles model constructor.
     * @property {module:model/AssignableRoles}
     */
    AssignableRoles: AssignableRoles,
    /**
     * The ClassicAdminToInvite model constructor.
     * @property {module:model/ClassicAdminToInvite}
     */
    ClassicAdminToInvite: ClassicAdminToInvite,
    /**
     * The ClassicAgentToInvite model constructor.
     * @property {module:model/ClassicAgentToInvite}
     */
    ClassicAgentToInvite: ClassicAgentToInvite,
    /**
     * The ClassicManagerPermissions model constructor.
     * @property {module:model/ClassicManagerPermissions}
     */
    ClassicManagerPermissions: ClassicManagerPermissions,
    /**
     * The ClassicManagerToInvite model constructor.
     * @property {module:model/ClassicManagerToInvite}
     */
    ClassicManagerToInvite: ClassicManagerToInvite,
    /**
     * The ClosingStatus model constructor.
     * @property {module:model/ClosingStatus}
     */
    ClosingStatus: ClosingStatus,
    /**
     * The ContactSide model constructor.
     * @property {module:model/ContactSide}
     */
    ContactSide: ContactSide,
    /**
     * The Country model constructor.
     * @property {module:model/Country}
     */
    Country: Country,
    /**
     * The Currency model constructor.
     * @property {module:model/Currency}
     */
    Currency: Currency,
    /**
     * The CustomData model constructor.
     * @property {module:model/CustomData}
     */
    CustomData: CustomData,
    /**
     * The DependsOn model constructor.
     * @property {module:model/DependsOn}
     */
    DependsOn: DependsOn,
    /**
     * The DesignatedOffice model constructor.
     * @property {module:model/DesignatedOffice}
     */
    DesignatedOffice: DesignatedOffice,
    /**
     * The DesignatedRegion model constructor.
     * @property {module:model/DesignatedRegion}
     */
    DesignatedRegion: DesignatedRegion,
    /**
     * The Document model constructor.
     * @property {module:model/Document}
     */
    Document: Document,
    /**
     * The DocumentUser model constructor.
     * @property {module:model/DocumentUser}
     */
    DocumentUser: DocumentUser,
    /**
     * The DocumentUserForCreate model constructor.
     * @property {module:model/DocumentUserForCreate}
     */
    DocumentUserForCreate: DocumentUserForCreate,
    /**
     * The ESignAccountRoleSettings model constructor.
     * @property {module:model/ESignAccountRoleSettings}
     */
    ESignAccountRoleSettings: ESignAccountRoleSettings,
    /**
     * The ESignPermissionProfile model constructor.
     * @property {module:model/ESignPermissionProfile}
     */
    ESignPermissionProfile: ESignPermissionProfile,
    /**
     * The ESignPermissionProfileList model constructor.
     * @property {module:model/ESignPermissionProfileList}
     */
    ESignPermissionProfileList: ESignPermissionProfileList,
    /**
     * The ExternalFormFillSession model constructor.
     * @property {module:model/ExternalFormFillSession}
     */
    ExternalFormFillSession: ExternalFormFillSession,
    /**
     * The ExternalFormFillSessionForCreate model constructor.
     * @property {module:model/ExternalFormFillSessionForCreate}
     */
    ExternalFormFillSessionForCreate: ExternalFormFillSessionForCreate,
    /**
     * The Field model constructor.
     * @property {module:model/Field}
     */
    Field: Field,
    /**
     * The FieldConfiguration model constructor.
     * @property {module:model/FieldConfiguration}
     */
    FieldConfiguration: FieldConfiguration,
    /**
     * The FieldData model constructor.
     * @property {module:model/FieldData}
     */
    FieldData: FieldData,
    /**
     * The FieldDataForCreate model constructor.
     * @property {module:model/FieldDataForCreate}
     */
    FieldDataForCreate: FieldDataForCreate,
    /**
     * The FieldDataForUpdate model constructor.
     * @property {module:model/FieldDataForUpdate}
     */
    FieldDataForUpdate: FieldDataForUpdate,
    /**
     * The FieldSet model constructor.
     * @property {module:model/FieldSet}
     */
    FieldSet: FieldSet,
    /**
     * The FieldsCustomDataFilterType model constructor.
     * @property {module:model/FieldsCustomDataFilterType}
     */
    FieldsCustomDataFilterType: FieldsCustomDataFilterType,
    /**
     * The FinancingType model constructor.
     * @property {module:model/FinancingType}
     */
    FinancingType: FinancingType,
    /**
     * The FormDetails model constructor.
     * @property {module:model/FormDetails}
     */
    FormDetails: FormDetails,
    /**
     * The FormForAdd model constructor.
     * @property {module:model/FormForAdd}
     */
    FormForAdd: FormForAdd,
    /**
     * The FormGroup model constructor.
     * @property {module:model/FormGroup}
     */
    FormGroup: FormGroup,
    /**
     * The FormGroupForCreate model constructor.
     * @property {module:model/FormGroupForCreate}
     */
    FormGroupForCreate: FormGroupForCreate,
    /**
     * The FormGroupForUpdate model constructor.
     * @property {module:model/FormGroupForUpdate}
     */
    FormGroupForUpdate: FormGroupForUpdate,
    /**
     * The FormGroupFormToAssign model constructor.
     * @property {module:model/FormGroupFormToAssign}
     */
    FormGroupFormToAssign: FormGroupFormToAssign,
    /**
     * The FormGroupSummary model constructor.
     * @property {module:model/FormGroupSummary}
     */
    FormGroupSummary: FormGroupSummary,
    /**
     * The FormGroupSummaryList model constructor.
     * @property {module:model/FormGroupSummaryList}
     */
    FormGroupSummaryList: FormGroupSummaryList,
    /**
     * The FormLibrarySummary model constructor.
     * @property {module:model/FormLibrarySummary}
     */
    FormLibrarySummary: FormLibrarySummary,
    /**
     * The FormLibrarySummaryList model constructor.
     * @property {module:model/FormLibrarySummaryList}
     */
    FormLibrarySummaryList: FormLibrarySummaryList,
    /**
     * The FormSummary model constructor.
     * @property {module:model/FormSummary}
     */
    FormSummary: FormSummary,
    /**
     * The FormSummaryList model constructor.
     * @property {module:model/FormSummaryList}
     */
    FormSummaryList: FormSummaryList,
    /**
     * The GlobalActivityTypes model constructor.
     * @property {module:model/GlobalActivityTypes}
     */
    GlobalActivityTypes: GlobalActivityTypes,
    /**
     * The GlobalClosingStatuses model constructor.
     * @property {module:model/GlobalClosingStatuses}
     */
    GlobalClosingStatuses: GlobalClosingStatuses,
    /**
     * The GlobalContactSides model constructor.
     * @property {module:model/GlobalContactSides}
     */
    GlobalContactSides: GlobalContactSides,
    /**
     * The GlobalCountries model constructor.
     * @property {module:model/GlobalCountries}
     */
    GlobalCountries: GlobalCountries,
    /**
     * The GlobalCurrencies model constructor.
     * @property {module:model/GlobalCurrencies}
     */
    GlobalCurrencies: GlobalCurrencies,
    /**
     * The GlobalFinancingTypes model constructor.
     * @property {module:model/GlobalFinancingTypes}
     */
    GlobalFinancingTypes: GlobalFinancingTypes,
    /**
     * The GlobalOriginsOfLeads model constructor.
     * @property {module:model/GlobalOriginsOfLeads}
     */
    GlobalOriginsOfLeads: GlobalOriginsOfLeads,
    /**
     * The GlobalPropertyTypes model constructor.
     * @property {module:model/GlobalPropertyTypes}
     */
    GlobalPropertyTypes: GlobalPropertyTypes,
    /**
     * The GlobalRoomContactTypes model constructor.
     * @property {module:model/GlobalRoomContactTypes}
     */
    GlobalRoomContactTypes: GlobalRoomContactTypes,
    /**
     * The GlobalSellerDecisionTypes model constructor.
     * @property {module:model/GlobalSellerDecisionTypes}
     */
    GlobalSellerDecisionTypes: GlobalSellerDecisionTypes,
    /**
     * The GlobalSpecialCircumstanceTypes model constructor.
     * @property {module:model/GlobalSpecialCircumstanceTypes}
     */
    GlobalSpecialCircumstanceTypes: GlobalSpecialCircumstanceTypes,
    /**
     * The GlobalStates model constructor.
     * @property {module:model/GlobalStates}
     */
    GlobalStates: GlobalStates,
    /**
     * The GlobalTaskDateTypes model constructor.
     * @property {module:model/GlobalTaskDateTypes}
     */
    GlobalTaskDateTypes: GlobalTaskDateTypes,
    /**
     * The GlobalTaskResponsibilityTypes model constructor.
     * @property {module:model/GlobalTaskResponsibilityTypes}
     */
    GlobalTaskResponsibilityTypes: GlobalTaskResponsibilityTypes,
    /**
     * The GlobalTaskStatuses model constructor.
     * @property {module:model/GlobalTaskStatuses}
     */
    GlobalTaskStatuses: GlobalTaskStatuses,
    /**
     * The GlobalTimeZones model constructor.
     * @property {module:model/GlobalTimeZones}
     */
    GlobalTimeZones: GlobalTimeZones,
    /**
     * The GlobalTransactionSides model constructor.
     * @property {module:model/GlobalTransactionSides}
     */
    GlobalTransactionSides: GlobalTransactionSides,
    /**
     * The GroupForm model constructor.
     * @property {module:model/GroupForm}
     */
    GroupForm: GroupForm,
    /**
     * The LockedOutDetails model constructor.
     * @property {module:model/LockedOutDetails}
     */
    LockedOutDetails: LockedOutDetails,
    /**
     * The MemberSortingOption model constructor.
     * @property {module:model/MemberSortingOption}
     */
    MemberSortingOption: MemberSortingOption,
    /**
     * The Office model constructor.
     * @property {module:model/Office}
     */
    Office: Office,
    /**
     * The OfficeForCreate model constructor.
     * @property {module:model/OfficeForCreate}
     */
    OfficeForCreate: OfficeForCreate,
    /**
     * The OfficeReferenceCount model constructor.
     * @property {module:model/OfficeReferenceCount}
     */
    OfficeReferenceCount: OfficeReferenceCount,
    /**
     * The OfficeReferenceCountList model constructor.
     * @property {module:model/OfficeReferenceCountList}
     */
    OfficeReferenceCountList: OfficeReferenceCountList,
    /**
     * The OfficeSummary model constructor.
     * @property {module:model/OfficeSummary}
     */
    OfficeSummary: OfficeSummary,
    /**
     * The OfficeSummaryList model constructor.
     * @property {module:model/OfficeSummaryList}
     */
    OfficeSummaryList: OfficeSummaryList,
    /**
     * The OriginOfLead model constructor.
     * @property {module:model/OriginOfLead}
     */
    OriginOfLead: OriginOfLead,
    /**
     * The Permissions model constructor.
     * @property {module:model/Permissions}
     */
    Permissions: Permissions,
    /**
     * The ProductVersion model constructor.
     * @property {module:model/ProductVersion}
     */
    ProductVersion: ProductVersion,
    /**
     * The PropertyType model constructor.
     * @property {module:model/PropertyType}
     */
    PropertyType: PropertyType,
    /**
     * The Region model constructor.
     * @property {module:model/Region}
     */
    Region: Region,
    /**
     * The RegionReferenceCount model constructor.
     * @property {module:model/RegionReferenceCount}
     */
    RegionReferenceCount: RegionReferenceCount,
    /**
     * The RegionReferenceCountList model constructor.
     * @property {module:model/RegionReferenceCountList}
     */
    RegionReferenceCountList: RegionReferenceCountList,
    /**
     * The RegionSummary model constructor.
     * @property {module:model/RegionSummary}
     */
    RegionSummary: RegionSummary,
    /**
     * The RegionSummaryList model constructor.
     * @property {module:model/RegionSummaryList}
     */
    RegionSummaryList: RegionSummaryList,
    /**
     * The Role model constructor.
     * @property {module:model/Role}
     */
    Role: Role,
    /**
     * The RoleForCreate model constructor.
     * @property {module:model/RoleForCreate}
     */
    RoleForCreate: RoleForCreate,
    /**
     * The RoleForUpdate model constructor.
     * @property {module:model/RoleForUpdate}
     */
    RoleForUpdate: RoleForUpdate,
    /**
     * The RoleSummary model constructor.
     * @property {module:model/RoleSummary}
     */
    RoleSummary: RoleSummary,
    /**
     * The RoleSummaryList model constructor.
     * @property {module:model/RoleSummaryList}
     */
    RoleSummaryList: RoleSummaryList,
    /**
     * The Room model constructor.
     * @property {module:model/Room}
     */
    Room: Room,
    /**
     * The RoomContactType model constructor.
     * @property {module:model/RoomContactType}
     */
    RoomContactType: RoomContactType,
    /**
     * The RoomDocument model constructor.
     * @property {module:model/RoomDocument}
     */
    RoomDocument: RoomDocument,
    /**
     * The RoomDocumentList model constructor.
     * @property {module:model/RoomDocumentList}
     */
    RoomDocumentList: RoomDocumentList,
    /**
     * The RoomDocumentOwner model constructor.
     * @property {module:model/RoomDocumentOwner}
     */
    RoomDocumentOwner: RoomDocumentOwner,
    /**
     * The RoomFolder model constructor.
     * @property {module:model/RoomFolder}
     */
    RoomFolder: RoomFolder,
    /**
     * The RoomFolderList model constructor.
     * @property {module:model/RoomFolderList}
     */
    RoomFolderList: RoomFolderList,
    /**
     * The RoomForCreate model constructor.
     * @property {module:model/RoomForCreate}
     */
    RoomForCreate: RoomForCreate,
    /**
     * The RoomInvite model constructor.
     * @property {module:model/RoomInvite}
     */
    RoomInvite: RoomInvite,
    /**
     * The RoomInviteResponse model constructor.
     * @property {module:model/RoomInviteResponse}
     */
    RoomInviteResponse: RoomInviteResponse,
    /**
     * The RoomPicture model constructor.
     * @property {module:model/RoomPicture}
     */
    RoomPicture: RoomPicture,
    /**
     * The RoomStatus model constructor.
     * @property {module:model/RoomStatus}
     */
    RoomStatus: RoomStatus,
    /**
     * The RoomSummary model constructor.
     * @property {module:model/RoomSummary}
     */
    RoomSummary: RoomSummary,
    /**
     * The RoomSummaryList model constructor.
     * @property {module:model/RoomSummaryList}
     */
    RoomSummaryList: RoomSummaryList,
    /**
     * The RoomTemplate model constructor.
     * @property {module:model/RoomTemplate}
     */
    RoomTemplate: RoomTemplate,
    /**
     * The RoomTemplatesSummaryList model constructor.
     * @property {module:model/RoomTemplatesSummaryList}
     */
    RoomTemplatesSummaryList: RoomTemplatesSummaryList,
    /**
     * The RoomUser model constructor.
     * @property {module:model/RoomUser}
     */
    RoomUser: RoomUser,
    /**
     * The RoomUserForUpdate model constructor.
     * @property {module:model/RoomUserForUpdate}
     */
    RoomUserForUpdate: RoomUserForUpdate,
    /**
     * The RoomUserRemovalDetail model constructor.
     * @property {module:model/RoomUserRemovalDetail}
     */
    RoomUserRemovalDetail: RoomUserRemovalDetail,
    /**
     * The RoomUserSortingOption model constructor.
     * @property {module:model/RoomUserSortingOption}
     */
    RoomUserSortingOption: RoomUserSortingOption,
    /**
     * The RoomUserSummary model constructor.
     * @property {module:model/RoomUserSummary}
     */
    RoomUserSummary: RoomUserSummary,
    /**
     * The RoomUsersResult model constructor.
     * @property {module:model/RoomUsersResult}
     */
    RoomUsersResult: RoomUsersResult,
    /**
     * The SelectListFieldOption model constructor.
     * @property {module:model/SelectListFieldOption}
     */
    SelectListFieldOption: SelectListFieldOption,
    /**
     * The SellerDecisionType model constructor.
     * @property {module:model/SellerDecisionType}
     */
    SellerDecisionType: SellerDecisionType,
    /**
     * The SpecialCircumstanceType model constructor.
     * @property {module:model/SpecialCircumstanceType}
     */
    SpecialCircumstanceType: SpecialCircumstanceType,
    /**
     * The State model constructor.
     * @property {module:model/State}
     */
    State: State,
    /**
     * The TaskDateType model constructor.
     * @property {module:model/TaskDateType}
     */
    TaskDateType: TaskDateType,
    /**
     * The TaskList model constructor.
     * @property {module:model/TaskList}
     */
    TaskList: TaskList,
    /**
     * The TaskListForCreate model constructor.
     * @property {module:model/TaskListForCreate}
     */
    TaskListForCreate: TaskListForCreate,
    /**
     * The TaskListSummary model constructor.
     * @property {module:model/TaskListSummary}
     */
    TaskListSummary: TaskListSummary,
    /**
     * The TaskListSummaryList model constructor.
     * @property {module:model/TaskListSummaryList}
     */
    TaskListSummaryList: TaskListSummaryList,
    /**
     * The TaskListTemplate model constructor.
     * @property {module:model/TaskListTemplate}
     */
    TaskListTemplate: TaskListTemplate,
    /**
     * The TaskListTemplateList model constructor.
     * @property {module:model/TaskListTemplateList}
     */
    TaskListTemplateList: TaskListTemplateList,
    /**
     * The TaskResponsibilityType model constructor.
     * @property {module:model/TaskResponsibilityType}
     */
    TaskResponsibilityType: TaskResponsibilityType,
    /**
     * The TaskStatus model constructor.
     * @property {module:model/TaskStatus}
     */
    TaskStatus: TaskStatus,
    /**
     * The TaskSummary model constructor.
     * @property {module:model/TaskSummary}
     */
    TaskSummary: TaskSummary,
    /**
     * The TimeZone model constructor.
     * @property {module:model/TimeZone}
     */
    TimeZone: TimeZone,
    /**
     * The TransactionSide model constructor.
     * @property {module:model/TransactionSide}
     */
    TransactionSide: TransactionSide,
    /**
     * The User model constructor.
     * @property {module:model/User}
     */
    User: User,
    /**
     * The UserForUpdate model constructor.
     * @property {module:model/UserForUpdate}
     */
    UserForUpdate: UserForUpdate,
    /**
     * The UserSummary model constructor.
     * @property {module:model/UserSummary}
     */
    UserSummary: UserSummary,
    /**
     * The UserSummaryList model constructor.
     * @property {module:model/UserSummaryList}
     */
    UserSummaryList: UserSummaryList,
    /**
     * The UserToInvite model constructor.
     * @property {module:model/UserToInvite}
     */
    UserToInvite: UserToInvite,
    /**
     * The AccountsApi service constructor.
     * @property {module:api/AccountsApi}
     */
    AccountsApi: AccountsApi,
    /**
     * The ActivityTypesApi service constructor.
     * @property {module:api/ActivityTypesApi}
     */
    ActivityTypesApi: ActivityTypesApi,
    /**
     * The ClosingStatusesApi service constructor.
     * @property {module:api/ClosingStatusesApi}
     */
    ClosingStatusesApi: ClosingStatusesApi,
    /**
     * The ContactSidesApi service constructor.
     * @property {module:api/ContactSidesApi}
     */
    ContactSidesApi: ContactSidesApi,
    /**
     * The CountriesApi service constructor.
     * @property {module:api/CountriesApi}
     */
    CountriesApi: CountriesApi,
    /**
     * The CurrenciesApi service constructor.
     * @property {module:api/CurrenciesApi}
     */
    CurrenciesApi: CurrenciesApi,
    /**
     * The DocumentsApi service constructor.
     * @property {module:api/DocumentsApi}
     */
    DocumentsApi: DocumentsApi,
    /**
     * The ESignPermissionProfilesApi service constructor.
     * @property {module:api/ESignPermissionProfilesApi}
     */
    ESignPermissionProfilesApi: ESignPermissionProfilesApi,
    /**
     * The ExternalFormFillSessionsApi service constructor.
     * @property {module:api/ExternalFormFillSessionsApi}
     */
    ExternalFormFillSessionsApi: ExternalFormFillSessionsApi,
    /**
     * The FieldsApi service constructor.
     * @property {module:api/FieldsApi}
     */
    FieldsApi: FieldsApi,
    /**
     * The FinancingTypesApi service constructor.
     * @property {module:api/FinancingTypesApi}
     */
    FinancingTypesApi: FinancingTypesApi,
    /**
     * The FormDetailsApi service constructor.
     * @property {module:api/FormDetailsApi}
     */
    FormDetailsApi: FormDetailsApi,
    /**
     * The FormGroupsApi service constructor.
     * @property {module:api/FormGroupsApi}
     */
    FormGroupsApi: FormGroupsApi,
    /**
     * The FormLibrariesApi service constructor.
     * @property {module:api/FormLibrariesApi}
     */
    FormLibrariesApi: FormLibrariesApi,
    /**
     * The OfficesApi service constructor.
     * @property {module:api/OfficesApi}
     */
    OfficesApi: OfficesApi,
    /**
     * The OriginsOfLeadsApi service constructor.
     * @property {module:api/OriginsOfLeadsApi}
     */
    OriginsOfLeadsApi: OriginsOfLeadsApi,
    /**
     * The PropertyTypesApi service constructor.
     * @property {module:api/PropertyTypesApi}
     */
    PropertyTypesApi: PropertyTypesApi,
    /**
     * The RegionsApi service constructor.
     * @property {module:api/RegionsApi}
     */
    RegionsApi: RegionsApi,
    /**
     * The RolesApi service constructor.
     * @property {module:api/RolesApi}
     */
    RolesApi: RolesApi,
    /**
     * The RoomContactTypesApi service constructor.
     * @property {module:api/RoomContactTypesApi}
     */
    RoomContactTypesApi: RoomContactTypesApi,
    /**
     * The RoomFoldersApi service constructor.
     * @property {module:api/RoomFoldersApi}
     */
    RoomFoldersApi: RoomFoldersApi,
    /**
     * The RoomTemplatesApi service constructor.
     * @property {module:api/RoomTemplatesApi}
     */
    RoomTemplatesApi: RoomTemplatesApi,
    /**
     * The RoomsApi service constructor.
     * @property {module:api/RoomsApi}
     */
    RoomsApi: RoomsApi,
    /**
     * The SellerDecisionTypesApi service constructor.
     * @property {module:api/SellerDecisionTypesApi}
     */
    SellerDecisionTypesApi: SellerDecisionTypesApi,
    /**
     * The SpecialCircumstanceTypesApi service constructor.
     * @property {module:api/SpecialCircumstanceTypesApi}
     */
    SpecialCircumstanceTypesApi: SpecialCircumstanceTypesApi,
    /**
     * The StatesApi service constructor.
     * @property {module:api/StatesApi}
     */
    StatesApi: StatesApi,
    /**
     * The TaskDateTypesApi service constructor.
     * @property {module:api/TaskDateTypesApi}
     */
    TaskDateTypesApi: TaskDateTypesApi,
    /**
     * The TaskListTemplatesApi service constructor.
     * @property {module:api/TaskListTemplatesApi}
     */
    TaskListTemplatesApi: TaskListTemplatesApi,
    /**
     * The TaskListsApi service constructor.
     * @property {module:api/TaskListsApi}
     */
    TaskListsApi: TaskListsApi,
    /**
     * The TaskResponsibilityTypesApi service constructor.
     * @property {module:api/TaskResponsibilityTypesApi}
     */
    TaskResponsibilityTypesApi: TaskResponsibilityTypesApi,
    /**
     * The TaskStatusesApi service constructor.
     * @property {module:api/TaskStatusesApi}
     */
    TaskStatusesApi: TaskStatusesApi,
    /**
     * The TimeZonesApi service constructor.
     * @property {module:api/TimeZonesApi}
     */
    TimeZonesApi: TimeZonesApi,
    /**
     * The TransactionSidesApi service constructor.
     * @property {module:api/TransactionSidesApi}
     */
    TransactionSidesApi: TransactionSidesApi,
    /**
     * The UsersApi service constructor.
     * @property {module:api/UsersApi}
     */
    UsersApi: UsersApi
  };

  return exports;
}));