package qlog

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/francoispqt/gojay"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mevent struct{}

var _ eventDetails = mevent{}

func (mevent) Category() category                   { return categoryConnectivity }
func (mevent) Name() string                         { return "mevent" }
func (mevent) IsNil() bool                          { return false }
func (mevent) MarshalJSONObject(enc *gojay.Encoder) { enc.StringKey("event", "details") }

var _ = Describe("Events", func() {
	It("marshals the fields before the event details", func() {
		now := time.Now()

		buf := &bytes.Buffer{}
		enc := gojay.NewEncoder(buf)
		Expect(enc.Encode(event{
			Time:         now,
			eventDetails: mevent{},
		})).To(Succeed())

		var decoded []interface{}
		Expect(json.Unmarshal(buf.Bytes(), &decoded)).To(Succeed())
		Expect(decoded).To(HaveLen(4))

		// 1st field
		Expect(eventFields[0]).To(Equal("time"))
		Expect(time.Unix(0, int64(1e6*decoded[0].(float64)))).To(BeTemporally("~", now, 2*time.Microsecond))

		// 2nd field
		Expect(eventFields[1]).To(Equal("category"))
		Expect(decoded[1].(string)).To(Equal(categoryConnectivity.String()))

		// 3rd field
		Expect(eventFields[2]).To(Equal("event"))
		Expect(decoded[2].(string)).To(Equal("mevent"))

		// 4th field
		Expect(eventFields[3]).To(Equal("data"))
		Expect(decoded[3].(map[string]interface{})["event"]).To(Equal("details"))
	})
})
