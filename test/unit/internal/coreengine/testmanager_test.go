package coreengine_test

import (
	"testing"

	"gitlab.com/citihub/probr/internal/coreengine"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestTestStatus(t *testing.T) {
	ts := coreengine.Pending
	assert.Equal(t, ts.String(), "Pending")

	ts = coreengine.Running
	assert.Equal(t, ts.String(), "Running")

	ts = coreengine.CompleteSuccess
	assert.Equal(t, ts.String(), "CompleteSuccess")

	ts = coreengine.CompleteFail
	assert.Equal(t, ts.String(), "CompleteFail")

	ts = coreengine.Error
	assert.Equal(t, ts.String(), "Error")
}

func TestGetAvailableTests(t *testing.T) {
	alltests := coreengine.GetAvailableTests()

	//not implemented yet, so expect alltests to be nil
	assert.Nil(t, alltests)
}

func TestAddGetTest(t *testing.T) {
	// create a test and add it to the TestStore

	//test descriptor ... (general)
	grp := coreengine.CloudDriver
	cat := coreengine.General
	name := "account_manager"
	td := coreengine.TestDescriptor{Group: grp, Category: cat, Name: name}

	uuid1 := uuid.New().String()
	sat1 := coreengine.Pending

	test1 := coreengine.Test{
		UUID:           &uuid1,
		TestDescriptor: &td,
		Status:         &sat1,
	}

	assert.NotNil(t, test1)

	// get the test mgr
	tm := coreengine.NewTestManager()

	assert.NotNil(t, tm)

	tsuuid := tm.AddTest(&test1)

	// now try and get it back ...
	rtntest, err := tm.GetTest(tsuuid)

	assert.Nil(t, err)
	assert.NotNil(t, rtntest)
	assert.Equal(t, 1, len(*rtntest))

	assert.Equal(t, test1.UUID, (*rtntest)[0].UUID, "test UUID %v is NOT the same as the returned test UUID %V", test1.UUID, (*rtntest)[0].UUID)

}


func addTest(tm *coreengine.TestStore, testname string, grp coreengine.Group, cat coreengine.Category) {
	
	td := coreengine.TestDescriptor{Group: grp, Category: cat, Name: testname}

	uuid1 := uuid.New().String()
	sat := coreengine.Pending

	test := coreengine.Test{
		UUID:           &uuid1,
		TestDescriptor: &td,
		Status:         &sat,
	}

	//add - don't worry about the rtn uuid
	tm.AddTest(&test)

}
