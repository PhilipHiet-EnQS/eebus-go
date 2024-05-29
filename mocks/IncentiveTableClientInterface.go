// Code generated by mockery v2.42.1. DO NOT EDIT.

package mocks

import (
	model "github.com/enbility/spine-go/model"
	mock "github.com/stretchr/testify/mock"
)

// IncentiveTableClientInterface is an autogenerated mock type for the IncentiveTableClientInterface type
type IncentiveTableClientInterface struct {
	mock.Mock
}

type IncentiveTableClientInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *IncentiveTableClientInterface) EXPECT() *IncentiveTableClientInterface_Expecter {
	return &IncentiveTableClientInterface_Expecter{mock: &_m.Mock}
}

// RequestConstraints provides a mock function with given fields:
func (_m *IncentiveTableClientInterface) RequestConstraints() (*model.MsgCounterType, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for RequestConstraints")
	}

	var r0 *model.MsgCounterType
	var r1 error
	if rf, ok := ret.Get(0).(func() (*model.MsgCounterType, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *model.MsgCounterType); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.MsgCounterType)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IncentiveTableClientInterface_RequestConstraints_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RequestConstraints'
type IncentiveTableClientInterface_RequestConstraints_Call struct {
	*mock.Call
}

// RequestConstraints is a helper method to define mock.On call
func (_e *IncentiveTableClientInterface_Expecter) RequestConstraints() *IncentiveTableClientInterface_RequestConstraints_Call {
	return &IncentiveTableClientInterface_RequestConstraints_Call{Call: _e.mock.On("RequestConstraints")}
}

func (_c *IncentiveTableClientInterface_RequestConstraints_Call) Run(run func()) *IncentiveTableClientInterface_RequestConstraints_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *IncentiveTableClientInterface_RequestConstraints_Call) Return(_a0 *model.MsgCounterType, _a1 error) *IncentiveTableClientInterface_RequestConstraints_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IncentiveTableClientInterface_RequestConstraints_Call) RunAndReturn(run func() (*model.MsgCounterType, error)) *IncentiveTableClientInterface_RequestConstraints_Call {
	_c.Call.Return(run)
	return _c
}

// RequestDescriptions provides a mock function with given fields:
func (_m *IncentiveTableClientInterface) RequestDescriptions() (*model.MsgCounterType, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for RequestDescriptions")
	}

	var r0 *model.MsgCounterType
	var r1 error
	if rf, ok := ret.Get(0).(func() (*model.MsgCounterType, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *model.MsgCounterType); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.MsgCounterType)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IncentiveTableClientInterface_RequestDescriptions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RequestDescriptions'
type IncentiveTableClientInterface_RequestDescriptions_Call struct {
	*mock.Call
}

// RequestDescriptions is a helper method to define mock.On call
func (_e *IncentiveTableClientInterface_Expecter) RequestDescriptions() *IncentiveTableClientInterface_RequestDescriptions_Call {
	return &IncentiveTableClientInterface_RequestDescriptions_Call{Call: _e.mock.On("RequestDescriptions")}
}

func (_c *IncentiveTableClientInterface_RequestDescriptions_Call) Run(run func()) *IncentiveTableClientInterface_RequestDescriptions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *IncentiveTableClientInterface_RequestDescriptions_Call) Return(_a0 *model.MsgCounterType, _a1 error) *IncentiveTableClientInterface_RequestDescriptions_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IncentiveTableClientInterface_RequestDescriptions_Call) RunAndReturn(run func() (*model.MsgCounterType, error)) *IncentiveTableClientInterface_RequestDescriptions_Call {
	_c.Call.Return(run)
	return _c
}

// RequestValues provides a mock function with given fields:
func (_m *IncentiveTableClientInterface) RequestValues() (*model.MsgCounterType, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for RequestValues")
	}

	var r0 *model.MsgCounterType
	var r1 error
	if rf, ok := ret.Get(0).(func() (*model.MsgCounterType, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *model.MsgCounterType); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.MsgCounterType)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IncentiveTableClientInterface_RequestValues_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RequestValues'
type IncentiveTableClientInterface_RequestValues_Call struct {
	*mock.Call
}

// RequestValues is a helper method to define mock.On call
func (_e *IncentiveTableClientInterface_Expecter) RequestValues() *IncentiveTableClientInterface_RequestValues_Call {
	return &IncentiveTableClientInterface_RequestValues_Call{Call: _e.mock.On("RequestValues")}
}

func (_c *IncentiveTableClientInterface_RequestValues_Call) Run(run func()) *IncentiveTableClientInterface_RequestValues_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *IncentiveTableClientInterface_RequestValues_Call) Return(_a0 *model.MsgCounterType, _a1 error) *IncentiveTableClientInterface_RequestValues_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IncentiveTableClientInterface_RequestValues_Call) RunAndReturn(run func() (*model.MsgCounterType, error)) *IncentiveTableClientInterface_RequestValues_Call {
	_c.Call.Return(run)
	return _c
}

// WriteDescriptions provides a mock function with given fields: data
func (_m *IncentiveTableClientInterface) WriteDescriptions(data []model.IncentiveTableDescriptionType) (*model.MsgCounterType, error) {
	ret := _m.Called(data)

	if len(ret) == 0 {
		panic("no return value specified for WriteDescriptions")
	}

	var r0 *model.MsgCounterType
	var r1 error
	if rf, ok := ret.Get(0).(func([]model.IncentiveTableDescriptionType) (*model.MsgCounterType, error)); ok {
		return rf(data)
	}
	if rf, ok := ret.Get(0).(func([]model.IncentiveTableDescriptionType) *model.MsgCounterType); ok {
		r0 = rf(data)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.MsgCounterType)
		}
	}

	if rf, ok := ret.Get(1).(func([]model.IncentiveTableDescriptionType) error); ok {
		r1 = rf(data)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IncentiveTableClientInterface_WriteDescriptions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WriteDescriptions'
type IncentiveTableClientInterface_WriteDescriptions_Call struct {
	*mock.Call
}

// WriteDescriptions is a helper method to define mock.On call
//   - data []model.IncentiveTableDescriptionType
func (_e *IncentiveTableClientInterface_Expecter) WriteDescriptions(data interface{}) *IncentiveTableClientInterface_WriteDescriptions_Call {
	return &IncentiveTableClientInterface_WriteDescriptions_Call{Call: _e.mock.On("WriteDescriptions", data)}
}

func (_c *IncentiveTableClientInterface_WriteDescriptions_Call) Run(run func(data []model.IncentiveTableDescriptionType)) *IncentiveTableClientInterface_WriteDescriptions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]model.IncentiveTableDescriptionType))
	})
	return _c
}

func (_c *IncentiveTableClientInterface_WriteDescriptions_Call) Return(_a0 *model.MsgCounterType, _a1 error) *IncentiveTableClientInterface_WriteDescriptions_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IncentiveTableClientInterface_WriteDescriptions_Call) RunAndReturn(run func([]model.IncentiveTableDescriptionType) (*model.MsgCounterType, error)) *IncentiveTableClientInterface_WriteDescriptions_Call {
	_c.Call.Return(run)
	return _c
}

// WriteValues provides a mock function with given fields: data
func (_m *IncentiveTableClientInterface) WriteValues(data []model.IncentiveTableType) (*model.MsgCounterType, error) {
	ret := _m.Called(data)

	if len(ret) == 0 {
		panic("no return value specified for WriteValues")
	}

	var r0 *model.MsgCounterType
	var r1 error
	if rf, ok := ret.Get(0).(func([]model.IncentiveTableType) (*model.MsgCounterType, error)); ok {
		return rf(data)
	}
	if rf, ok := ret.Get(0).(func([]model.IncentiveTableType) *model.MsgCounterType); ok {
		r0 = rf(data)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.MsgCounterType)
		}
	}

	if rf, ok := ret.Get(1).(func([]model.IncentiveTableType) error); ok {
		r1 = rf(data)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IncentiveTableClientInterface_WriteValues_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WriteValues'
type IncentiveTableClientInterface_WriteValues_Call struct {
	*mock.Call
}

// WriteValues is a helper method to define mock.On call
//   - data []model.IncentiveTableType
func (_e *IncentiveTableClientInterface_Expecter) WriteValues(data interface{}) *IncentiveTableClientInterface_WriteValues_Call {
	return &IncentiveTableClientInterface_WriteValues_Call{Call: _e.mock.On("WriteValues", data)}
}

func (_c *IncentiveTableClientInterface_WriteValues_Call) Run(run func(data []model.IncentiveTableType)) *IncentiveTableClientInterface_WriteValues_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]model.IncentiveTableType))
	})
	return _c
}

func (_c *IncentiveTableClientInterface_WriteValues_Call) Return(_a0 *model.MsgCounterType, _a1 error) *IncentiveTableClientInterface_WriteValues_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IncentiveTableClientInterface_WriteValues_Call) RunAndReturn(run func([]model.IncentiveTableType) (*model.MsgCounterType, error)) *IncentiveTableClientInterface_WriteValues_Call {
	_c.Call.Return(run)
	return _c
}

// NewIncentiveTableClientInterface creates a new instance of IncentiveTableClientInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIncentiveTableClientInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *IncentiveTableClientInterface {
	mock := &IncentiveTableClientInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}