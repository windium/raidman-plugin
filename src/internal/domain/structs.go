package domain

// Constants
const (
	KeysPath       = "/boot/config/plugins/dynamix.my.servers/keys"
	PushTokensPath = "/boot/config/plugins/raidman/push_tokens.json"
)

type ApiKeyStruct struct {
	Key string `json:"key"`
}

// XML Structures for parsing virsh dumpxml
type DomainXml struct {
	Description string   `xml:"description"`
	DeviceList  Devices  `xml:"devices"`
	Metadata    Metadata `xml:"metadata"`
}

type Metadata struct {
	VmTemplate VmTemplate `xml:"vmtemplate"`
}

type VmTemplate struct {
	Icon string `xml:"icon,attr"`
	Name string `xml:"name,attr"`
	Os   string `xml:"os,attr"`
}

type Devices struct {
	Disks      []Disk      `xml:"disk"`
	Interfaces []Interface `xml:"interface"`
	Graphics   []Graphics  `xml:"graphics"`
}

type Disk struct {
	Type   string     `xml:"type,attr"`
	Device string     `xml:"device,attr"`
	Source DiskSource `xml:"source"`
	Target DiskTarget `xml:"target"`
	Serial string     `xml:"serial"`
	Boot   *DiskBoot  `xml:"boot"`
}

type DiskSource struct {
	File string `xml:"file,attr"`
	Dev  string `xml:"dev,attr"` // for block devices
}

type DiskTarget struct {
	Dev string `xml:"dev,attr"`
	Bus string `xml:"bus,attr"`
}

type DiskBoot struct {
	Order int `xml:"order,attr"`
}

type Interface struct {
	Mac    MacAddress      `xml:"mac"`
	Source InterfaceSource `xml:"source"`
	Model  InterfaceModel  `xml:"model"`
}

type MacAddress struct {
	Address string `xml:"address,attr"`
}

type InterfaceSource struct {
	Bridge string `xml:"bridge,attr"`
	Dev    string `xml:"dev,attr"` // for direct/macvtap
}

type InterfaceModel struct {
	Type string `xml:"type,attr"`
}

type Graphics struct {
	Type     string `xml:"type,attr"`
	Port     int    `xml:"port,attr"`
	AutoPort string `xml:"autoport,attr"`
}

// JSON Output Structures
type VmDisk struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	Bus       string `json:"bus"`
	Type      string `json:"type"`
	Serial    string `json:"serial"`
	BootOrder int    `json:"bootOrder"`
}

type VmInterface struct {
	Mac       string `json:"mac"`
	Model     string `json:"model"`
	Network   string `json:"network"`
	IpAddress string `json:"ipAddress"`
}

type VmGraphics struct {
	Type string `json:"type"`
	Port int    `json:"port"`
}

type VmInfo struct {
	Name          string        `json:"name"`
	DomId         string        `json:"domId"`
	Uuid          string        `json:"uuid"`
	OsType        string        `json:"osType"`
	DetailedState string        `json:"detailedState"`
	CpuTime       string        `json:"cpuTime"`
	Autostart     bool          `json:"autostart"`
	Memory        int64         `json:"memory"` // in Bytes
	Vcpus         int           `json:"vcpus"`
	Persistent    bool          `json:"persistent"`
	ManagedSave   string        `json:"managedSave"`
	SecurityModel string        `json:"securityModel"`
	SecurityDOI   string        `json:"securityDOI"`
	Description   string        `json:"description"`
	Icon          string        `json:"icon"`
	Disks         []VmDisk      `json:"disks"`
	Interfaces    []VmInterface `json:"interfaces"`
	Graphics      []VmGraphics  `json:"graphics"`
}

type AutostartRequest struct {
	Vm      string `json:"vm"`
	Enabled bool   `json:"enabled"`
}

type ArrayStatus struct {
	State string `json:"state"`
	// Parity Check Details
	ParityCheckStatus *ParityCheckStatus `json:"parityCheckStatus"`
	Parities          []ArrayDisk        `json:"parities"`
	Disks             []ArrayDisk        `json:"disks"`
	Caches            []ArrayDisk        `json:"caches"`
	Boot              *ArrayDisk         `json:"boot"`
	Unassigned        []ArrayDisk        `json:"unassigned"`
}

type ParityCheckStatus struct {
	Status   string `json:"status"` // "RUNNING", "PAUSED", "IDLE"
	Running  bool   `json:"running"`
	Paused   bool   `json:"paused"`
	Progress string `json:"progress"` // "0.0" to "100.0"
	Speed    string `json:"speed"`    // e.g. "120.5 MB/s" or just number
	Duration int64  `json:"duration"` // Seconds
	Date     string `json:"date"`     // Unix Timestamp or Date String
	Errors   int64  `json:"errors"`
	Pos      int64  `json:"pos"`
	Total    int64  `json:"total"`
}

type ArrayDisk struct {
	Id         string `json:"id"`
	Idx        int    `json:"idx"`
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
	Device     string `json:"device"`
	State      string `json:"state"`
	Size       int64  `json:"size"`
	NumReads   int64  `json:"numReads"`
	NumWrites  int64  `json:"numWrites"`
	NumErrors  int64  `json:"numErrors"`
	Temp       int    `json:"temp"`
}

// Push Notification Structures
type PushTokenRequest struct {
	Token string `json:"token"`
}

type InternalPushRequest struct {
	Event       string `json:"event"`
	Subject     string `json:"subject"`
	Description string `json:"description"`
	Link        string `json:"link"`
	Severity    string `json:"severity"`
	Content     string `json:"content"`
}

type ExpoPushMessage struct {
	To       string                 `json:"to"`
	Title    string                 `json:"title"`
	Body     string                 `json:"body"`
	Data     map[string]interface{} `json:"data"`
	Sound    string                 `json:"sound"`
	Subtitle string                 `json:"subtitle,omitempty"`
}
