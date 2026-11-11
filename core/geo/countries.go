package geo

import "strings"

// countryData maps ISO 3166-1 alpha-2 to the most common browser locale and
// the most populous IANA zone. Used when a provider omits the zone and for
// language "auto". Multi-zone countries (US, RU, BR, ...) get their most
// populous zone; providers normally return the precise one.
var countryData = map[string][2]string{
	"AD": {"ca-AD", "Europe/Andorra"}, "AE": {"ar-AE", "Asia/Dubai"}, "AF": {"fa-AF", "Asia/Kabul"},
	"AL": {"sq-AL", "Europe/Tirane"}, "AM": {"hy-AM", "Asia/Yerevan"}, "AO": {"pt-AO", "Africa/Luanda"},
	"AR": {"es-AR", "America/Argentina/Buenos_Aires"}, "AT": {"de-AT", "Europe/Vienna"},
	"AU": {"en-AU", "Australia/Sydney"}, "AZ": {"az-AZ", "Asia/Baku"}, "BA": {"bs-BA", "Europe/Sarajevo"},
	"BD": {"bn-BD", "Asia/Dhaka"}, "BE": {"nl-BE", "Europe/Brussels"}, "BG": {"bg-BG", "Europe/Sofia"},
	"BH": {"ar-BH", "Asia/Bahrain"}, "BO": {"es-BO", "America/La_Paz"}, "BR": {"pt-BR", "America/Sao_Paulo"},
	"BY": {"be-BY", "Europe/Minsk"}, "CA": {"en-CA", "America/Toronto"}, "CH": {"de-CH", "Europe/Zurich"},
	"CL": {"es-CL", "America/Santiago"}, "CN": {"zh-CN", "Asia/Shanghai"}, "CO": {"es-CO", "America/Bogota"},
	"CR": {"es-CR", "America/Costa_Rica"}, "CY": {"el-CY", "Asia/Nicosia"}, "CZ": {"cs-CZ", "Europe/Prague"},
	"DE": {"de-DE", "Europe/Berlin"}, "DK": {"da-DK", "Europe/Copenhagen"}, "DO": {"es-DO", "America/Santo_Domingo"},
	"DZ": {"ar-DZ", "Africa/Algiers"}, "EC": {"es-EC", "America/Guayaquil"}, "EE": {"et-EE", "Europe/Tallinn"},
	"EG": {"ar-EG", "Africa/Cairo"}, "ES": {"es-ES", "Europe/Madrid"}, "ET": {"am-ET", "Africa/Addis_Ababa"},
	"FI": {"fi-FI", "Europe/Helsinki"}, "FR": {"fr-FR", "Europe/Paris"}, "GB": {"en-GB", "Europe/London"},
	"GE": {"ka-GE", "Asia/Tbilisi"}, "GH": {"en-GH", "Africa/Accra"}, "GR": {"el-GR", "Europe/Athens"},
	"GT": {"es-GT", "America/Guatemala"}, "HK": {"zh-HK", "Asia/Hong_Kong"}, "HN": {"es-HN", "America/Tegucigalpa"},
	"HR": {"hr-HR", "Europe/Zagreb"}, "HU": {"hu-HU", "Europe/Budapest"}, "ID": {"id-ID", "Asia/Jakarta"},
	"IE": {"en-IE", "Europe/Dublin"}, "IL": {"he-IL", "Asia/Jerusalem"}, "IN": {"en-IN", "Asia/Kolkata"},
	"IQ": {"ar-IQ", "Asia/Baghdad"}, "IR": {"fa-IR", "Asia/Tehran"}, "IS": {"is-IS", "Atlantic/Reykjavik"},
	"IT": {"it-IT", "Europe/Rome"}, "JM": {"en-JM", "America/Jamaica"}, "JO": {"ar-JO", "Asia/Amman"},
	"JP": {"ja-JP", "Asia/Tokyo"}, "KE": {"en-KE", "Africa/Nairobi"}, "KG": {"ky-KG", "Asia/Bishkek"},
	"KH": {"km-KH", "Asia/Phnom_Penh"}, "KR": {"ko-KR", "Asia/Seoul"}, "KW": {"ar-KW", "Asia/Kuwait"},
	"KZ": {"kk-KZ", "Asia/Almaty"}, "LB": {"ar-LB", "Asia/Beirut"}, "LK": {"si-LK", "Asia/Colombo"},
	"LT": {"lt-LT", "Europe/Vilnius"}, "LU": {"fr-LU", "Europe/Luxembourg"}, "LV": {"lv-LV", "Europe/Riga"},
	"LY": {"ar-LY", "Africa/Tripoli"}, "MA": {"ar-MA", "Africa/Casablanca"}, "MD": {"ro-MD", "Europe/Chisinau"},
	"ME": {"sr-ME", "Europe/Podgorica"}, "MK": {"mk-MK", "Europe/Skopje"}, "MM": {"my-MM", "Asia/Yangon"},
	"MN": {"mn-MN", "Asia/Ulaanbaatar"}, "MT": {"mt-MT", "Europe/Malta"}, "MX": {"es-MX", "America/Mexico_City"},
	"MY": {"ms-MY", "Asia/Kuala_Lumpur"}, "NG": {"en-NG", "Africa/Lagos"}, "NI": {"es-NI", "America/Managua"},
	"NL": {"nl-NL", "Europe/Amsterdam"}, "NO": {"nb-NO", "Europe/Oslo"}, "NP": {"ne-NP", "Asia/Kathmandu"},
	"NZ": {"en-NZ", "Pacific/Auckland"}, "OM": {"ar-OM", "Asia/Muscat"}, "PA": {"es-PA", "America/Panama"},
	"PE": {"es-PE", "America/Lima"}, "PH": {"en-PH", "Asia/Manila"}, "PK": {"ur-PK", "Asia/Karachi"},
	"PL": {"pl-PL", "Europe/Warsaw"}, "PR": {"es-PR", "America/Puerto_Rico"}, "PT": {"pt-PT", "Europe/Lisbon"},
	"PY": {"es-PY", "America/Asuncion"}, "QA": {"ar-QA", "Asia/Qatar"}, "RO": {"ro-RO", "Europe/Bucharest"},
	"RS": {"sr-RS", "Europe/Belgrade"}, "RU": {"ru-RU", "Europe/Moscow"}, "SA": {"ar-SA", "Asia/Riyadh"},
	"SE": {"sv-SE", "Europe/Stockholm"}, "SG": {"en-SG", "Asia/Singapore"}, "SI": {"sl-SI", "Europe/Ljubljana"},
	"SK": {"sk-SK", "Europe/Bratislava"}, "SN": {"fr-SN", "Africa/Dakar"}, "SV": {"es-SV", "America/El_Salvador"},
	"SY": {"ar-SY", "Asia/Damascus"}, "TH": {"th-TH", "Asia/Bangkok"}, "TJ": {"tg-TJ", "Asia/Dushanbe"},
	"TM": {"tk-TM", "Asia/Ashgabat"}, "TN": {"ar-TN", "Africa/Tunis"}, "TR": {"tr-TR", "Europe/Istanbul"},
	"TW": {"zh-TW", "Asia/Taipei"}, "TZ": {"sw-TZ", "Africa/Dar_es_Salaam"}, "UA": {"uk-UA", "Europe/Kyiv"},
	"UG": {"en-UG", "Africa/Kampala"}, "US": {"en-US", "America/New_York"}, "UY": {"es-UY", "America/Montevideo"},
	"UZ": {"uz-UZ", "Asia/Tashkent"}, "VE": {"es-VE", "America/Caracas"}, "VN": {"vi-VN", "Asia/Ho_Chi_Minh"},
	"YE": {"ar-YE", "Asia/Aden"}, "ZA": {"en-ZA", "Africa/Johannesburg"}, "ZW": {"en-ZW", "Africa/Harare"},
}

// CountryLanguage returns the usual browser locale for a country ("en-US"
// when unknown).
func CountryLanguage(cc string) string {
	if d, ok := countryData[strings.ToUpper(cc)]; ok {
		return d[0]
	}
	return "en-US"
}

// CountryTimezone returns the most populous IANA zone of a country, or "".
func CountryTimezone(cc string) string {
	if d, ok := countryData[strings.ToUpper(cc)]; ok {
		return d[1]
	}
	return ""
}
