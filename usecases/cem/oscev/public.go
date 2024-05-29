package oscev

import (
	"github.com/enbility/eebus-go/api"
	"github.com/enbility/eebus-go/features/client"
	ucapi "github.com/enbility/eebus-go/usecases/api"
	"github.com/enbility/eebus-go/usecases/internal"
	spineapi "github.com/enbility/spine-go/api"
	"github.com/enbility/spine-go/model"
	"github.com/enbility/spine-go/util"
)

// return the min, max, default limits for each phase of the connected EV
//
// possible errors:
//   - ErrDataNotAvailable if no such measurement is (yet) available
//   - and others
func (e *CemOSCEV) CurrentLimits(entity spineapi.EntityRemoteInterface) ([]float64, []float64, []float64, error) {
	if !e.IsCompatibleEntity(entity) {
		return nil, nil, nil, api.ErrNoCompatibleEntity
	}

	ec, err := client.NewElectricalConnection(e.LocalEntity, entity)
	if err != nil {
		return nil, nil, nil, err
	}

	return ec.GetPhaseCurrentLimits()
}

// return the current loadcontrol recommendation limits
//
// parameters:
//   - entity: the entity of the EV
//
// return values:
//   - limits: per phase data
//
// possible errors:
//   - ErrDataNotAvailable if no such limit is (yet) available
//   - and others
func (e *CemOSCEV) LoadControlLimits(entity spineapi.EntityRemoteInterface) (
	limits []ucapi.LoadLimitsPhase, resultErr error) {
	if !e.IsCompatibleEntity(entity) {
		return nil, api.ErrNoCompatibleEntity
	}

	filter := model.LoadControlLimitDescriptionDataType{
		LimitType:     util.Ptr(model.LoadControlLimitTypeTypeMaxValueLimit),
		LimitCategory: util.Ptr(model.LoadControlCategoryTypeRecommendation),
		ScopeType:     util.Ptr(model.ScopeTypeTypeOverloadProtection),
	}
	return internal.LoadControlLimits(e.LocalEntity, entity, filter)
}

// send new LoadControlLimits to the remote EV
//
// parameters:
//   - limits: a set of limits containing phase specific limit data
//
// recommendations:
// Sets a recommended charge power in A for each phase. This is mainly
// used if the EV and EVSE communicate via ISO15118 to support charging excess solar power.
// The EV either needs to support the Optimization of Self Consumption usecase or
// the EVSE needs to be able map the recommendations into oligation limits which then
// works for all EVs communication either via IEC61851 or ISO15118.
func (e *CemOSCEV) WriteLoadControlLimits(entity spineapi.EntityRemoteInterface, limits []ucapi.LoadLimitsPhase) (*model.MsgCounterType, error) {
	if !e.IsCompatibleEntity(entity) {
		return nil, api.ErrNoCompatibleEntity
	}

	return internal.WriteLoadControlLimits(e.LocalEntity, entity, model.LoadControlCategoryTypeRecommendation, limits)
}