// Code generated by mockery v2.42.1. DO NOT EDIT.

package mocks

import (
	api "github.com/enbility/eebus-go/api"
	mock "github.com/stretchr/testify/mock"

	model "github.com/enbility/spine-go/model"

	spine_goapi "github.com/enbility/spine-go/api"
)

// UseCaseInterface is an autogenerated mock type for the UseCaseInterface type
type UseCaseInterface struct {
	mock.Mock
}

type UseCaseInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *UseCaseInterface) EXPECT() *UseCaseInterface_Expecter {
	return &UseCaseInterface_Expecter{mock: &_m.Mock}
}

// AddFeatures provides a mock function with given fields:
func (_m *UseCaseInterface) AddFeatures() {
	_m.Called()
}

// UseCaseInterface_AddFeatures_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddFeatures'
type UseCaseInterface_AddFeatures_Call struct {
	*mock.Call
}

// AddFeatures is a helper method to define mock.On call
func (_e *UseCaseInterface_Expecter) AddFeatures() *UseCaseInterface_AddFeatures_Call {
	return &UseCaseInterface_AddFeatures_Call{Call: _e.mock.On("AddFeatures")}
}

func (_c *UseCaseInterface_AddFeatures_Call) Run(run func()) *UseCaseInterface_AddFeatures_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *UseCaseInterface_AddFeatures_Call) Return() *UseCaseInterface_AddFeatures_Call {
	_c.Call.Return()
	return _c
}

func (_c *UseCaseInterface_AddFeatures_Call) RunAndReturn(run func()) *UseCaseInterface_AddFeatures_Call {
	_c.Call.Return(run)
	return _c
}

// AddUseCase provides a mock function with given fields:
func (_m *UseCaseInterface) AddUseCase() {
	_m.Called()
}

// UseCaseInterface_AddUseCase_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddUseCase'
type UseCaseInterface_AddUseCase_Call struct {
	*mock.Call
}

// AddUseCase is a helper method to define mock.On call
func (_e *UseCaseInterface_Expecter) AddUseCase() *UseCaseInterface_AddUseCase_Call {
	return &UseCaseInterface_AddUseCase_Call{Call: _e.mock.On("AddUseCase")}
}

func (_c *UseCaseInterface_AddUseCase_Call) Run(run func()) *UseCaseInterface_AddUseCase_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *UseCaseInterface_AddUseCase_Call) Return() *UseCaseInterface_AddUseCase_Call {
	_c.Call.Return()
	return _c
}

func (_c *UseCaseInterface_AddUseCase_Call) RunAndReturn(run func()) *UseCaseInterface_AddUseCase_Call {
	_c.Call.Return(run)
	return _c
}

// HasSupportForUseCaseScenarios provides a mock function with given fields: entity, scenarios
func (_m *UseCaseInterface) HasSupportForUseCaseScenarios(entity spine_goapi.EntityRemoteInterface, scenarios []model.UseCaseScenarioSupportType) bool {
	ret := _m.Called(entity, scenarios)

	if len(ret) == 0 {
		panic("no return value specified for HasSupportForUseCaseScenarios")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface, []model.UseCaseScenarioSupportType) bool); ok {
		r0 = rf(entity, scenarios)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// UseCaseInterface_HasSupportForUseCaseScenarios_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HasSupportForUseCaseScenarios'
type UseCaseInterface_HasSupportForUseCaseScenarios_Call struct {
	*mock.Call
}

// HasSupportForUseCaseScenarios is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
//   - scenarios []model.UseCaseScenarioSupportType
func (_e *UseCaseInterface_Expecter) HasSupportForUseCaseScenarios(entity interface{}, scenarios interface{}) *UseCaseInterface_HasSupportForUseCaseScenarios_Call {
	return &UseCaseInterface_HasSupportForUseCaseScenarios_Call{Call: _e.mock.On("HasSupportForUseCaseScenarios", entity, scenarios)}
}

func (_c *UseCaseInterface_HasSupportForUseCaseScenarios_Call) Run(run func(entity spine_goapi.EntityRemoteInterface, scenarios []model.UseCaseScenarioSupportType)) *UseCaseInterface_HasSupportForUseCaseScenarios_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface), args[1].([]model.UseCaseScenarioSupportType))
	})
	return _c
}

func (_c *UseCaseInterface_HasSupportForUseCaseScenarios_Call) Return(_a0 bool) *UseCaseInterface_HasSupportForUseCaseScenarios_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *UseCaseInterface_HasSupportForUseCaseScenarios_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface, []model.UseCaseScenarioSupportType) bool) *UseCaseInterface_HasSupportForUseCaseScenarios_Call {
	_c.Call.Return(run)
	return _c
}

// IsCompatibleEntityType provides a mock function with given fields: entity
func (_m *UseCaseInterface) IsCompatibleEntityType(entity spine_goapi.EntityRemoteInterface) bool {
	ret := _m.Called(entity)

	if len(ret) == 0 {
		panic("no return value specified for IsCompatibleEntityType")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) bool); ok {
		r0 = rf(entity)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// UseCaseInterface_IsCompatibleEntityType_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IsCompatibleEntityType'
type UseCaseInterface_IsCompatibleEntityType_Call struct {
	*mock.Call
}

// IsCompatibleEntityType is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
func (_e *UseCaseInterface_Expecter) IsCompatibleEntityType(entity interface{}) *UseCaseInterface_IsCompatibleEntityType_Call {
	return &UseCaseInterface_IsCompatibleEntityType_Call{Call: _e.mock.On("IsCompatibleEntityType", entity)}
}

func (_c *UseCaseInterface_IsCompatibleEntityType_Call) Run(run func(entity spine_goapi.EntityRemoteInterface)) *UseCaseInterface_IsCompatibleEntityType_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *UseCaseInterface_IsCompatibleEntityType_Call) Return(_a0 bool) *UseCaseInterface_IsCompatibleEntityType_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *UseCaseInterface_IsCompatibleEntityType_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) bool) *UseCaseInterface_IsCompatibleEntityType_Call {
	_c.Call.Return(run)
	return _c
}

// IsUseCaseSupported provides a mock function with given fields: remoteEntity
func (_m *UseCaseInterface) IsUseCaseSupported(remoteEntity spine_goapi.EntityRemoteInterface) (bool, error) {
	ret := _m.Called(remoteEntity)

	if len(ret) == 0 {
		panic("no return value specified for IsUseCaseSupported")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) (bool, error)); ok {
		return rf(remoteEntity)
	}
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) bool); ok {
		r0 = rf(remoteEntity)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(spine_goapi.EntityRemoteInterface) error); ok {
		r1 = rf(remoteEntity)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UseCaseInterface_IsUseCaseSupported_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IsUseCaseSupported'
type UseCaseInterface_IsUseCaseSupported_Call struct {
	*mock.Call
}

// IsUseCaseSupported is a helper method to define mock.On call
//   - remoteEntity spine_goapi.EntityRemoteInterface
func (_e *UseCaseInterface_Expecter) IsUseCaseSupported(remoteEntity interface{}) *UseCaseInterface_IsUseCaseSupported_Call {
	return &UseCaseInterface_IsUseCaseSupported_Call{Call: _e.mock.On("IsUseCaseSupported", remoteEntity)}
}

func (_c *UseCaseInterface_IsUseCaseSupported_Call) Run(run func(remoteEntity spine_goapi.EntityRemoteInterface)) *UseCaseInterface_IsUseCaseSupported_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *UseCaseInterface_IsUseCaseSupported_Call) Return(_a0 bool, _a1 error) *UseCaseInterface_IsUseCaseSupported_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *UseCaseInterface_IsUseCaseSupported_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) (bool, error)) *UseCaseInterface_IsUseCaseSupported_Call {
	_c.Call.Return(run)
	return _c
}

// RemoteEntities provides a mock function with given fields:
func (_m *UseCaseInterface) RemoteEntities() []api.RemoteEntityScenarios {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for RemoteEntities")
	}

	var r0 []api.RemoteEntityScenarios
	if rf, ok := ret.Get(0).(func() []api.RemoteEntityScenarios); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]api.RemoteEntityScenarios)
		}
	}

	return r0
}

// UseCaseInterface_RemoteEntities_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoteEntities'
type UseCaseInterface_RemoteEntities_Call struct {
	*mock.Call
}

// RemoteEntities is a helper method to define mock.On call
func (_e *UseCaseInterface_Expecter) RemoteEntities() *UseCaseInterface_RemoteEntities_Call {
	return &UseCaseInterface_RemoteEntities_Call{Call: _e.mock.On("RemoteEntities")}
}

func (_c *UseCaseInterface_RemoteEntities_Call) Run(run func()) *UseCaseInterface_RemoteEntities_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *UseCaseInterface_RemoteEntities_Call) Return(_a0 []api.RemoteEntityScenarios) *UseCaseInterface_RemoteEntities_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *UseCaseInterface_RemoteEntities_Call) RunAndReturn(run func() []api.RemoteEntityScenarios) *UseCaseInterface_RemoteEntities_Call {
	_c.Call.Return(run)
	return _c
}

// RemoveUseCase provides a mock function with given fields:
func (_m *UseCaseInterface) RemoveUseCase() {
	_m.Called()
}

// UseCaseInterface_RemoveUseCase_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoveUseCase'
type UseCaseInterface_RemoveUseCase_Call struct {
	*mock.Call
}

// RemoveUseCase is a helper method to define mock.On call
func (_e *UseCaseInterface_Expecter) RemoveUseCase() *UseCaseInterface_RemoveUseCase_Call {
	return &UseCaseInterface_RemoveUseCase_Call{Call: _e.mock.On("RemoveUseCase")}
}

func (_c *UseCaseInterface_RemoveUseCase_Call) Run(run func()) *UseCaseInterface_RemoveUseCase_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *UseCaseInterface_RemoveUseCase_Call) Return() *UseCaseInterface_RemoveUseCase_Call {
	_c.Call.Return()
	return _c
}

func (_c *UseCaseInterface_RemoveUseCase_Call) RunAndReturn(run func()) *UseCaseInterface_RemoveUseCase_Call {
	_c.Call.Return(run)
	return _c
}

// SupportedUseCaseScenarios provides a mock function with given fields: entity
func (_m *UseCaseInterface) SupportedUseCaseScenarios(entity spine_goapi.EntityRemoteInterface) []model.UseCaseScenarioSupportType {
	ret := _m.Called(entity)

	if len(ret) == 0 {
		panic("no return value specified for SupportedUseCaseScenarios")
	}

	var r0 []model.UseCaseScenarioSupportType
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) []model.UseCaseScenarioSupportType); ok {
		r0 = rf(entity)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.UseCaseScenarioSupportType)
		}
	}

	return r0
}

// UseCaseInterface_SupportedUseCaseScenarios_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SupportedUseCaseScenarios'
type UseCaseInterface_SupportedUseCaseScenarios_Call struct {
	*mock.Call
}

// SupportedUseCaseScenarios is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
func (_e *UseCaseInterface_Expecter) SupportedUseCaseScenarios(entity interface{}) *UseCaseInterface_SupportedUseCaseScenarios_Call {
	return &UseCaseInterface_SupportedUseCaseScenarios_Call{Call: _e.mock.On("SupportedUseCaseScenarios", entity)}
}

func (_c *UseCaseInterface_SupportedUseCaseScenarios_Call) Run(run func(entity spine_goapi.EntityRemoteInterface)) *UseCaseInterface_SupportedUseCaseScenarios_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *UseCaseInterface_SupportedUseCaseScenarios_Call) Return(_a0 []model.UseCaseScenarioSupportType) *UseCaseInterface_SupportedUseCaseScenarios_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *UseCaseInterface_SupportedUseCaseScenarios_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) []model.UseCaseScenarioSupportType) *UseCaseInterface_SupportedUseCaseScenarios_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateUseCaseAvailability provides a mock function with given fields: available
func (_m *UseCaseInterface) UpdateUseCaseAvailability(available bool) {
	_m.Called(available)
}

// UseCaseInterface_UpdateUseCaseAvailability_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateUseCaseAvailability'
type UseCaseInterface_UpdateUseCaseAvailability_Call struct {
	*mock.Call
}

// UpdateUseCaseAvailability is a helper method to define mock.On call
//   - available bool
func (_e *UseCaseInterface_Expecter) UpdateUseCaseAvailability(available interface{}) *UseCaseInterface_UpdateUseCaseAvailability_Call {
	return &UseCaseInterface_UpdateUseCaseAvailability_Call{Call: _e.mock.On("UpdateUseCaseAvailability", available)}
}

func (_c *UseCaseInterface_UpdateUseCaseAvailability_Call) Run(run func(available bool)) *UseCaseInterface_UpdateUseCaseAvailability_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(bool))
	})
	return _c
}

func (_c *UseCaseInterface_UpdateUseCaseAvailability_Call) Return() *UseCaseInterface_UpdateUseCaseAvailability_Call {
	_c.Call.Return()
	return _c
}

func (_c *UseCaseInterface_UpdateUseCaseAvailability_Call) RunAndReturn(run func(bool)) *UseCaseInterface_UpdateUseCaseAvailability_Call {
	_c.Call.Return(run)
	return _c
}

// NewUseCaseInterface creates a new instance of UseCaseInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewUseCaseInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *UseCaseInterface {
	mock := &UseCaseInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
