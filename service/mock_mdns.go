// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/enbility/eebus-go/service (interfaces: MdnsSearch,MdnsService)

// Package service is a generated GoMock package.
package service

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockMdnsSearch is a mock of MdnsSearch interface.
type MockMdnsSearch struct {
	ctrl     *gomock.Controller
	recorder *MockMdnsSearchMockRecorder
}

// MockMdnsSearchMockRecorder is the mock recorder for MockMdnsSearch.
type MockMdnsSearchMockRecorder struct {
	mock *MockMdnsSearch
}

// NewMockMdnsSearch creates a new mock instance.
func NewMockMdnsSearch(ctrl *gomock.Controller) *MockMdnsSearch {
	mock := &MockMdnsSearch{ctrl: ctrl}
	mock.recorder = &MockMdnsSearchMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMdnsSearch) EXPECT() *MockMdnsSearchMockRecorder {
	return m.recorder
}

// ReportMdnsEntries mocks base method.
func (m *MockMdnsSearch) ReportMdnsEntries(arg0 map[string]MdnsEntry) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportMdnsEntries", arg0)
}

// ReportMdnsEntries indicates an expected call of ReportMdnsEntries.
func (mr *MockMdnsSearchMockRecorder) ReportMdnsEntries(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportMdnsEntries", reflect.TypeOf((*MockMdnsSearch)(nil).ReportMdnsEntries), arg0)
}

// MockMdnsService is a mock of MdnsService interface.
type MockMdnsService struct {
	ctrl     *gomock.Controller
	recorder *MockMdnsServiceMockRecorder
}

// MockMdnsServiceMockRecorder is the mock recorder for MockMdnsService.
type MockMdnsServiceMockRecorder struct {
	mock *MockMdnsService
}

// NewMockMdnsService creates a new mock instance.
func NewMockMdnsService(ctrl *gomock.Controller) *MockMdnsService {
	mock := &MockMdnsService{ctrl: ctrl}
	mock.recorder = &MockMdnsServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMdnsService) EXPECT() *MockMdnsServiceMockRecorder {
	return m.recorder
}

// AnnounceMdnsEntry mocks base method.
func (m *MockMdnsService) AnnounceMdnsEntry() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AnnounceMdnsEntry")
	ret0, _ := ret[0].(error)
	return ret0
}

// AnnounceMdnsEntry indicates an expected call of AnnounceMdnsEntry.
func (mr *MockMdnsServiceMockRecorder) AnnounceMdnsEntry() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AnnounceMdnsEntry", reflect.TypeOf((*MockMdnsService)(nil).AnnounceMdnsEntry))
}

// RegisterMdnsSearch mocks base method.
func (m *MockMdnsService) RegisterMdnsSearch(arg0 MdnsSearch) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RegisterMdnsSearch", arg0)
}

// RegisterMdnsSearch indicates an expected call of RegisterMdnsSearch.
func (mr *MockMdnsServiceMockRecorder) RegisterMdnsSearch(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterMdnsSearch", reflect.TypeOf((*MockMdnsService)(nil).RegisterMdnsSearch), arg0)
}

// SetupMdnsService mocks base method.
func (m *MockMdnsService) SetupMdnsService() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetupMdnsService")
	ret0, _ := ret[0].(error)
	return ret0
}

// SetupMdnsService indicates an expected call of SetupMdnsService.
func (mr *MockMdnsServiceMockRecorder) SetupMdnsService() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetupMdnsService", reflect.TypeOf((*MockMdnsService)(nil).SetupMdnsService))
}

// ShutdownMdnsService mocks base method.
func (m *MockMdnsService) ShutdownMdnsService() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ShutdownMdnsService")
}

// ShutdownMdnsService indicates an expected call of ShutdownMdnsService.
func (mr *MockMdnsServiceMockRecorder) ShutdownMdnsService() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ShutdownMdnsService", reflect.TypeOf((*MockMdnsService)(nil).ShutdownMdnsService))
}

// UnannounceMdnsEntry mocks base method.
func (m *MockMdnsService) UnannounceMdnsEntry() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UnannounceMdnsEntry")
}

// UnannounceMdnsEntry indicates an expected call of UnannounceMdnsEntry.
func (mr *MockMdnsServiceMockRecorder) UnannounceMdnsEntry() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnannounceMdnsEntry", reflect.TypeOf((*MockMdnsService)(nil).UnannounceMdnsEntry))
}

// UnregisterMdnsSearch mocks base method.
func (m *MockMdnsService) UnregisterMdnsSearch(arg0 MdnsSearch) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UnregisterMdnsSearch", arg0)
}

// UnregisterMdnsSearch indicates an expected call of UnregisterMdnsSearch.
func (mr *MockMdnsServiceMockRecorder) UnregisterMdnsSearch(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnregisterMdnsSearch", reflect.TypeOf((*MockMdnsService)(nil).UnregisterMdnsSearch), arg0)
}