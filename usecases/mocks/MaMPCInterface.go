// Code generated by mockery v2.42.1. DO NOT EDIT.

package mocks

import (
	eebus_goapi "github.com/enbility/eebus-go/api"
	mock "github.com/stretchr/testify/mock"

	model "github.com/enbility/spine-go/model"

	spine_goapi "github.com/enbility/spine-go/api"
)

// MaMPCInterface is an autogenerated mock type for the MaMPCInterface type
type MaMPCInterface struct {
	mock.Mock
}

type MaMPCInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *MaMPCInterface) EXPECT() *MaMPCInterface_Expecter {
	return &MaMPCInterface_Expecter{mock: &_m.Mock}
}

// AddFeatures provides a mock function with given fields:
func (_m *MaMPCInterface) AddFeatures() {
	_m.Called()
}

// MaMPCInterface_AddFeatures_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddFeatures'
type MaMPCInterface_AddFeatures_Call struct {
	*mock.Call
}

// AddFeatures is a helper method to define mock.On call
func (_e *MaMPCInterface_Expecter) AddFeatures() *MaMPCInterface_AddFeatures_Call {
	return &MaMPCInterface_AddFeatures_Call{Call: _e.mock.On("AddFeatures")}
}

func (_c *MaMPCInterface_AddFeatures_Call) Run(run func()) *MaMPCInterface_AddFeatures_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MaMPCInterface_AddFeatures_Call) Return() *MaMPCInterface_AddFeatures_Call {
	_c.Call.Return()
	return _c
}

func (_c *MaMPCInterface_AddFeatures_Call) RunAndReturn(run func()) *MaMPCInterface_AddFeatures_Call {
	_c.Call.Return(run)
	return _c
}

// AddUseCase provides a mock function with given fields:
func (_m *MaMPCInterface) AddUseCase() {
	_m.Called()
}

// MaMPCInterface_AddUseCase_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddUseCase'
type MaMPCInterface_AddUseCase_Call struct {
	*mock.Call
}

// AddUseCase is a helper method to define mock.On call
func (_e *MaMPCInterface_Expecter) AddUseCase() *MaMPCInterface_AddUseCase_Call {
	return &MaMPCInterface_AddUseCase_Call{Call: _e.mock.On("AddUseCase")}
}

func (_c *MaMPCInterface_AddUseCase_Call) Run(run func()) *MaMPCInterface_AddUseCase_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MaMPCInterface_AddUseCase_Call) Return() *MaMPCInterface_AddUseCase_Call {
	_c.Call.Return()
	return _c
}

func (_c *MaMPCInterface_AddUseCase_Call) RunAndReturn(run func()) *MaMPCInterface_AddUseCase_Call {
	_c.Call.Return(run)
	return _c
}

// CurrentPerPhase provides a mock function with given fields: entity
func (_m *MaMPCInterface) CurrentPerPhase(entity spine_goapi.EntityRemoteInterface) ([]float64, error) {
	ret := _m.Called(entity)

	if len(ret) == 0 {
		panic("no return value specified for CurrentPerPhase")
	}

	var r0 []float64
	var r1 error
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) ([]float64, error)); ok {
		return rf(entity)
	}
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) []float64); ok {
		r0 = rf(entity)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]float64)
		}
	}

	if rf, ok := ret.Get(1).(func(spine_goapi.EntityRemoteInterface) error); ok {
		r1 = rf(entity)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MaMPCInterface_CurrentPerPhase_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CurrentPerPhase'
type MaMPCInterface_CurrentPerPhase_Call struct {
	*mock.Call
}

// CurrentPerPhase is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
func (_e *MaMPCInterface_Expecter) CurrentPerPhase(entity interface{}) *MaMPCInterface_CurrentPerPhase_Call {
	return &MaMPCInterface_CurrentPerPhase_Call{Call: _e.mock.On("CurrentPerPhase", entity)}
}

func (_c *MaMPCInterface_CurrentPerPhase_Call) Run(run func(entity spine_goapi.EntityRemoteInterface)) *MaMPCInterface_CurrentPerPhase_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *MaMPCInterface_CurrentPerPhase_Call) Return(_a0 []float64, _a1 error) *MaMPCInterface_CurrentPerPhase_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MaMPCInterface_CurrentPerPhase_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) ([]float64, error)) *MaMPCInterface_CurrentPerPhase_Call {
	_c.Call.Return(run)
	return _c
}

// EnergyConsumed provides a mock function with given fields: entity
func (_m *MaMPCInterface) EnergyConsumed(entity spine_goapi.EntityRemoteInterface) (float64, error) {
	ret := _m.Called(entity)

	if len(ret) == 0 {
		panic("no return value specified for EnergyConsumed")
	}

	var r0 float64
	var r1 error
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) (float64, error)); ok {
		return rf(entity)
	}
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) float64); ok {
		r0 = rf(entity)
	} else {
		r0 = ret.Get(0).(float64)
	}

	if rf, ok := ret.Get(1).(func(spine_goapi.EntityRemoteInterface) error); ok {
		r1 = rf(entity)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MaMPCInterface_EnergyConsumed_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EnergyConsumed'
type MaMPCInterface_EnergyConsumed_Call struct {
	*mock.Call
}

// EnergyConsumed is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
func (_e *MaMPCInterface_Expecter) EnergyConsumed(entity interface{}) *MaMPCInterface_EnergyConsumed_Call {
	return &MaMPCInterface_EnergyConsumed_Call{Call: _e.mock.On("EnergyConsumed", entity)}
}

func (_c *MaMPCInterface_EnergyConsumed_Call) Run(run func(entity spine_goapi.EntityRemoteInterface)) *MaMPCInterface_EnergyConsumed_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *MaMPCInterface_EnergyConsumed_Call) Return(_a0 float64, _a1 error) *MaMPCInterface_EnergyConsumed_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MaMPCInterface_EnergyConsumed_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) (float64, error)) *MaMPCInterface_EnergyConsumed_Call {
	_c.Call.Return(run)
	return _c
}

// EnergyProduced provides a mock function with given fields: entity
func (_m *MaMPCInterface) EnergyProduced(entity spine_goapi.EntityRemoteInterface) (float64, error) {
	ret := _m.Called(entity)

	if len(ret) == 0 {
		panic("no return value specified for EnergyProduced")
	}

	var r0 float64
	var r1 error
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) (float64, error)); ok {
		return rf(entity)
	}
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) float64); ok {
		r0 = rf(entity)
	} else {
		r0 = ret.Get(0).(float64)
	}

	if rf, ok := ret.Get(1).(func(spine_goapi.EntityRemoteInterface) error); ok {
		r1 = rf(entity)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MaMPCInterface_EnergyProduced_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EnergyProduced'
type MaMPCInterface_EnergyProduced_Call struct {
	*mock.Call
}

// EnergyProduced is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
func (_e *MaMPCInterface_Expecter) EnergyProduced(entity interface{}) *MaMPCInterface_EnergyProduced_Call {
	return &MaMPCInterface_EnergyProduced_Call{Call: _e.mock.On("EnergyProduced", entity)}
}

func (_c *MaMPCInterface_EnergyProduced_Call) Run(run func(entity spine_goapi.EntityRemoteInterface)) *MaMPCInterface_EnergyProduced_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *MaMPCInterface_EnergyProduced_Call) Return(_a0 float64, _a1 error) *MaMPCInterface_EnergyProduced_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MaMPCInterface_EnergyProduced_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) (float64, error)) *MaMPCInterface_EnergyProduced_Call {
	_c.Call.Return(run)
	return _c
}

// Frequency provides a mock function with given fields: entity
func (_m *MaMPCInterface) Frequency(entity spine_goapi.EntityRemoteInterface) (float64, error) {
	ret := _m.Called(entity)

	if len(ret) == 0 {
		panic("no return value specified for Frequency")
	}

	var r0 float64
	var r1 error
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) (float64, error)); ok {
		return rf(entity)
	}
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) float64); ok {
		r0 = rf(entity)
	} else {
		r0 = ret.Get(0).(float64)
	}

	if rf, ok := ret.Get(1).(func(spine_goapi.EntityRemoteInterface) error); ok {
		r1 = rf(entity)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MaMPCInterface_Frequency_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Frequency'
type MaMPCInterface_Frequency_Call struct {
	*mock.Call
}

// Frequency is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
func (_e *MaMPCInterface_Expecter) Frequency(entity interface{}) *MaMPCInterface_Frequency_Call {
	return &MaMPCInterface_Frequency_Call{Call: _e.mock.On("Frequency", entity)}
}

func (_c *MaMPCInterface_Frequency_Call) Run(run func(entity spine_goapi.EntityRemoteInterface)) *MaMPCInterface_Frequency_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *MaMPCInterface_Frequency_Call) Return(_a0 float64, _a1 error) *MaMPCInterface_Frequency_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MaMPCInterface_Frequency_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) (float64, error)) *MaMPCInterface_Frequency_Call {
	_c.Call.Return(run)
	return _c
}

// HasSupportForUseCaseScenarios provides a mock function with given fields: entity, scenarios
func (_m *MaMPCInterface) HasSupportForUseCaseScenarios(entity spine_goapi.EntityRemoteInterface, scenarios []model.UseCaseScenarioSupportType) bool {
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

// MaMPCInterface_HasSupportForUseCaseScenarios_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HasSupportForUseCaseScenarios'
type MaMPCInterface_HasSupportForUseCaseScenarios_Call struct {
	*mock.Call
}

// HasSupportForUseCaseScenarios is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
//   - scenarios []model.UseCaseScenarioSupportType
func (_e *MaMPCInterface_Expecter) HasSupportForUseCaseScenarios(entity interface{}, scenarios interface{}) *MaMPCInterface_HasSupportForUseCaseScenarios_Call {
	return &MaMPCInterface_HasSupportForUseCaseScenarios_Call{Call: _e.mock.On("HasSupportForUseCaseScenarios", entity, scenarios)}
}

func (_c *MaMPCInterface_HasSupportForUseCaseScenarios_Call) Run(run func(entity spine_goapi.EntityRemoteInterface, scenarios []model.UseCaseScenarioSupportType)) *MaMPCInterface_HasSupportForUseCaseScenarios_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface), args[1].([]model.UseCaseScenarioSupportType))
	})
	return _c
}

func (_c *MaMPCInterface_HasSupportForUseCaseScenarios_Call) Return(_a0 bool) *MaMPCInterface_HasSupportForUseCaseScenarios_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MaMPCInterface_HasSupportForUseCaseScenarios_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface, []model.UseCaseScenarioSupportType) bool) *MaMPCInterface_HasSupportForUseCaseScenarios_Call {
	_c.Call.Return(run)
	return _c
}

// IsCompatibleEntityType provides a mock function with given fields: entity
func (_m *MaMPCInterface) IsCompatibleEntityType(entity spine_goapi.EntityRemoteInterface) bool {
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

// MaMPCInterface_IsCompatibleEntityType_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IsCompatibleEntityType'
type MaMPCInterface_IsCompatibleEntityType_Call struct {
	*mock.Call
}

// IsCompatibleEntityType is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
func (_e *MaMPCInterface_Expecter) IsCompatibleEntityType(entity interface{}) *MaMPCInterface_IsCompatibleEntityType_Call {
	return &MaMPCInterface_IsCompatibleEntityType_Call{Call: _e.mock.On("IsCompatibleEntityType", entity)}
}

func (_c *MaMPCInterface_IsCompatibleEntityType_Call) Run(run func(entity spine_goapi.EntityRemoteInterface)) *MaMPCInterface_IsCompatibleEntityType_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *MaMPCInterface_IsCompatibleEntityType_Call) Return(_a0 bool) *MaMPCInterface_IsCompatibleEntityType_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MaMPCInterface_IsCompatibleEntityType_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) bool) *MaMPCInterface_IsCompatibleEntityType_Call {
	_c.Call.Return(run)
	return _c
}

// IsUseCaseSupported provides a mock function with given fields: remoteEntity
func (_m *MaMPCInterface) IsUseCaseSupported(remoteEntity spine_goapi.EntityRemoteInterface) (bool, error) {
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

// MaMPCInterface_IsUseCaseSupported_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IsUseCaseSupported'
type MaMPCInterface_IsUseCaseSupported_Call struct {
	*mock.Call
}

// IsUseCaseSupported is a helper method to define mock.On call
//   - remoteEntity spine_goapi.EntityRemoteInterface
func (_e *MaMPCInterface_Expecter) IsUseCaseSupported(remoteEntity interface{}) *MaMPCInterface_IsUseCaseSupported_Call {
	return &MaMPCInterface_IsUseCaseSupported_Call{Call: _e.mock.On("IsUseCaseSupported", remoteEntity)}
}

func (_c *MaMPCInterface_IsUseCaseSupported_Call) Run(run func(remoteEntity spine_goapi.EntityRemoteInterface)) *MaMPCInterface_IsUseCaseSupported_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *MaMPCInterface_IsUseCaseSupported_Call) Return(_a0 bool, _a1 error) *MaMPCInterface_IsUseCaseSupported_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MaMPCInterface_IsUseCaseSupported_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) (bool, error)) *MaMPCInterface_IsUseCaseSupported_Call {
	_c.Call.Return(run)
	return _c
}

// Power provides a mock function with given fields: entity
func (_m *MaMPCInterface) Power(entity spine_goapi.EntityRemoteInterface) (float64, error) {
	ret := _m.Called(entity)

	if len(ret) == 0 {
		panic("no return value specified for Power")
	}

	var r0 float64
	var r1 error
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) (float64, error)); ok {
		return rf(entity)
	}
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) float64); ok {
		r0 = rf(entity)
	} else {
		r0 = ret.Get(0).(float64)
	}

	if rf, ok := ret.Get(1).(func(spine_goapi.EntityRemoteInterface) error); ok {
		r1 = rf(entity)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MaMPCInterface_Power_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Power'
type MaMPCInterface_Power_Call struct {
	*mock.Call
}

// Power is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
func (_e *MaMPCInterface_Expecter) Power(entity interface{}) *MaMPCInterface_Power_Call {
	return &MaMPCInterface_Power_Call{Call: _e.mock.On("Power", entity)}
}

func (_c *MaMPCInterface_Power_Call) Run(run func(entity spine_goapi.EntityRemoteInterface)) *MaMPCInterface_Power_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *MaMPCInterface_Power_Call) Return(_a0 float64, _a1 error) *MaMPCInterface_Power_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MaMPCInterface_Power_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) (float64, error)) *MaMPCInterface_Power_Call {
	_c.Call.Return(run)
	return _c
}

// PowerPerPhase provides a mock function with given fields: entity
func (_m *MaMPCInterface) PowerPerPhase(entity spine_goapi.EntityRemoteInterface) ([]float64, error) {
	ret := _m.Called(entity)

	if len(ret) == 0 {
		panic("no return value specified for PowerPerPhase")
	}

	var r0 []float64
	var r1 error
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) ([]float64, error)); ok {
		return rf(entity)
	}
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) []float64); ok {
		r0 = rf(entity)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]float64)
		}
	}

	if rf, ok := ret.Get(1).(func(spine_goapi.EntityRemoteInterface) error); ok {
		r1 = rf(entity)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MaMPCInterface_PowerPerPhase_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'PowerPerPhase'
type MaMPCInterface_PowerPerPhase_Call struct {
	*mock.Call
}

// PowerPerPhase is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
func (_e *MaMPCInterface_Expecter) PowerPerPhase(entity interface{}) *MaMPCInterface_PowerPerPhase_Call {
	return &MaMPCInterface_PowerPerPhase_Call{Call: _e.mock.On("PowerPerPhase", entity)}
}

func (_c *MaMPCInterface_PowerPerPhase_Call) Run(run func(entity spine_goapi.EntityRemoteInterface)) *MaMPCInterface_PowerPerPhase_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *MaMPCInterface_PowerPerPhase_Call) Return(_a0 []float64, _a1 error) *MaMPCInterface_PowerPerPhase_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MaMPCInterface_PowerPerPhase_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) ([]float64, error)) *MaMPCInterface_PowerPerPhase_Call {
	_c.Call.Return(run)
	return _c
}

// RemoteEntities provides a mock function with given fields:
func (_m *MaMPCInterface) RemoteEntities() []eebus_goapi.RemoteEntityScenarios {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for RemoteEntities")
	}

	var r0 []eebus_goapi.RemoteEntityScenarios
	if rf, ok := ret.Get(0).(func() []eebus_goapi.RemoteEntityScenarios); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]eebus_goapi.RemoteEntityScenarios)
		}
	}

	return r0
}

// MaMPCInterface_RemoteEntities_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoteEntities'
type MaMPCInterface_RemoteEntities_Call struct {
	*mock.Call
}

// RemoteEntities is a helper method to define mock.On call
func (_e *MaMPCInterface_Expecter) RemoteEntities() *MaMPCInterface_RemoteEntities_Call {
	return &MaMPCInterface_RemoteEntities_Call{Call: _e.mock.On("RemoteEntities")}
}

func (_c *MaMPCInterface_RemoteEntities_Call) Run(run func()) *MaMPCInterface_RemoteEntities_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MaMPCInterface_RemoteEntities_Call) Return(_a0 []eebus_goapi.RemoteEntityScenarios) *MaMPCInterface_RemoteEntities_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MaMPCInterface_RemoteEntities_Call) RunAndReturn(run func() []eebus_goapi.RemoteEntityScenarios) *MaMPCInterface_RemoteEntities_Call {
	_c.Call.Return(run)
	return _c
}

// RemoveUseCase provides a mock function with given fields:
func (_m *MaMPCInterface) RemoveUseCase() {
	_m.Called()
}

// MaMPCInterface_RemoveUseCase_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoveUseCase'
type MaMPCInterface_RemoveUseCase_Call struct {
	*mock.Call
}

// RemoveUseCase is a helper method to define mock.On call
func (_e *MaMPCInterface_Expecter) RemoveUseCase() *MaMPCInterface_RemoveUseCase_Call {
	return &MaMPCInterface_RemoveUseCase_Call{Call: _e.mock.On("RemoveUseCase")}
}

func (_c *MaMPCInterface_RemoveUseCase_Call) Run(run func()) *MaMPCInterface_RemoveUseCase_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MaMPCInterface_RemoveUseCase_Call) Return() *MaMPCInterface_RemoveUseCase_Call {
	_c.Call.Return()
	return _c
}

func (_c *MaMPCInterface_RemoveUseCase_Call) RunAndReturn(run func()) *MaMPCInterface_RemoveUseCase_Call {
	_c.Call.Return(run)
	return _c
}

// SupportedUseCaseScenarios provides a mock function with given fields: entity
func (_m *MaMPCInterface) SupportedUseCaseScenarios(entity spine_goapi.EntityRemoteInterface) []model.UseCaseScenarioSupportType {
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

// MaMPCInterface_SupportedUseCaseScenarios_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SupportedUseCaseScenarios'
type MaMPCInterface_SupportedUseCaseScenarios_Call struct {
	*mock.Call
}

// SupportedUseCaseScenarios is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
func (_e *MaMPCInterface_Expecter) SupportedUseCaseScenarios(entity interface{}) *MaMPCInterface_SupportedUseCaseScenarios_Call {
	return &MaMPCInterface_SupportedUseCaseScenarios_Call{Call: _e.mock.On("SupportedUseCaseScenarios", entity)}
}

func (_c *MaMPCInterface_SupportedUseCaseScenarios_Call) Run(run func(entity spine_goapi.EntityRemoteInterface)) *MaMPCInterface_SupportedUseCaseScenarios_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *MaMPCInterface_SupportedUseCaseScenarios_Call) Return(_a0 []model.UseCaseScenarioSupportType) *MaMPCInterface_SupportedUseCaseScenarios_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MaMPCInterface_SupportedUseCaseScenarios_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) []model.UseCaseScenarioSupportType) *MaMPCInterface_SupportedUseCaseScenarios_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateUseCaseAvailability provides a mock function with given fields: available
func (_m *MaMPCInterface) UpdateUseCaseAvailability(available bool) {
	_m.Called(available)
}

// MaMPCInterface_UpdateUseCaseAvailability_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateUseCaseAvailability'
type MaMPCInterface_UpdateUseCaseAvailability_Call struct {
	*mock.Call
}

// UpdateUseCaseAvailability is a helper method to define mock.On call
//   - available bool
func (_e *MaMPCInterface_Expecter) UpdateUseCaseAvailability(available interface{}) *MaMPCInterface_UpdateUseCaseAvailability_Call {
	return &MaMPCInterface_UpdateUseCaseAvailability_Call{Call: _e.mock.On("UpdateUseCaseAvailability", available)}
}

func (_c *MaMPCInterface_UpdateUseCaseAvailability_Call) Run(run func(available bool)) *MaMPCInterface_UpdateUseCaseAvailability_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(bool))
	})
	return _c
}

func (_c *MaMPCInterface_UpdateUseCaseAvailability_Call) Return() *MaMPCInterface_UpdateUseCaseAvailability_Call {
	_c.Call.Return()
	return _c
}

func (_c *MaMPCInterface_UpdateUseCaseAvailability_Call) RunAndReturn(run func(bool)) *MaMPCInterface_UpdateUseCaseAvailability_Call {
	_c.Call.Return(run)
	return _c
}

// VoltagePerPhase provides a mock function with given fields: entity
func (_m *MaMPCInterface) VoltagePerPhase(entity spine_goapi.EntityRemoteInterface) ([]float64, error) {
	ret := _m.Called(entity)

	if len(ret) == 0 {
		panic("no return value specified for VoltagePerPhase")
	}

	var r0 []float64
	var r1 error
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) ([]float64, error)); ok {
		return rf(entity)
	}
	if rf, ok := ret.Get(0).(func(spine_goapi.EntityRemoteInterface) []float64); ok {
		r0 = rf(entity)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]float64)
		}
	}

	if rf, ok := ret.Get(1).(func(spine_goapi.EntityRemoteInterface) error); ok {
		r1 = rf(entity)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MaMPCInterface_VoltagePerPhase_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'VoltagePerPhase'
type MaMPCInterface_VoltagePerPhase_Call struct {
	*mock.Call
}

// VoltagePerPhase is a helper method to define mock.On call
//   - entity spine_goapi.EntityRemoteInterface
func (_e *MaMPCInterface_Expecter) VoltagePerPhase(entity interface{}) *MaMPCInterface_VoltagePerPhase_Call {
	return &MaMPCInterface_VoltagePerPhase_Call{Call: _e.mock.On("VoltagePerPhase", entity)}
}

func (_c *MaMPCInterface_VoltagePerPhase_Call) Run(run func(entity spine_goapi.EntityRemoteInterface)) *MaMPCInterface_VoltagePerPhase_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(spine_goapi.EntityRemoteInterface))
	})
	return _c
}

func (_c *MaMPCInterface_VoltagePerPhase_Call) Return(_a0 []float64, _a1 error) *MaMPCInterface_VoltagePerPhase_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MaMPCInterface_VoltagePerPhase_Call) RunAndReturn(run func(spine_goapi.EntityRemoteInterface) ([]float64, error)) *MaMPCInterface_VoltagePerPhase_Call {
	_c.Call.Return(run)
	return _c
}

// NewMaMPCInterface creates a new instance of MaMPCInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMaMPCInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *MaMPCInterface {
	mock := &MaMPCInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
