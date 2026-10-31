"""
Rule-Based Anomaly Detection Engine for AirBnBrrr
===================================================
A hybrid deterministic safety check algorithm:
1. Handles Sensor Offline/Disconnected states cleanly (checking for None/Null values).
2. Performs combined rule checks (Compressor Overheating, Reduced Cooling).
3. Performs individual sensor checks only if the sensor readings are non-null.
"""

def is_overheating(tel):
    try:
        return (
            tel.get("pzem_current") is not None and float(tel.get("pzem_current")) >= 8.8 and 
            tel.get("pzem_power") is not None and float(tel.get("pzem_power")) >= 1860.0 and 
            tel.get("vibration") is not None and float(tel.get("vibration")) >= 90.0
        )
    except Exception:
        return False

def is_reduced_cooling(tel):
    try:
        return (
            tel.get("ds18b20_temp1") is not None and float(tel.get("ds18b20_temp1")) >= 61.0 and
            tel.get("dht_temp") is not None and float(tel.get("dht_temp")) >= 21.0 and
            tel.get("ds18b20_temp2") is not None and float(tel.get("ds18b20_temp2")) >= 22.0
        )
    except Exception:
        return False

RULES = [
    # ── SENSOR OFFLINE ALERTS ──────────────────────────────────
    {
        "id": "dht_offline",
        "label": "DHT Sensor Offline",
        "description": "Checks if output air temperature or humidity is missing/null",
        "check": lambda tel: tel.get("dht_temp") is None or tel.get("dht_humidity") is None,
        "issue": "DHT Sensor Offline",
        "severity": "High",
        "root_cause": "The output air temperature or humidity reading is missing, indicating the DHT22 sensor is not communicating with the ESP32.",
        "recommended_action": "Check physical wiring of the DHT22 sensor to GPIO Pin 18 and verify VCC/GND power.",
        "normal_range": "Valid reading (non-null)",
        "measured_val_func": lambda tel: f"Temp: {tel.get('dht_temp')}°C, Hum: {tel.get('dht_humidity')}%",
        "unit": ""
    },
    {
        "id": "pzem_offline",
        "label": "Power Meter Offline",
        "description": "Checks if PZEM power meter readings are missing/null",
        "check": lambda tel: tel.get("pzem_voltage") is None or tel.get("pzem_current") is None,
        "issue": "Power Meter Offline",
        "severity": "High",
        "root_cause": "PZEM-004T power meter readings are missing, indicating serial UART communication loss.",
        "recommended_action": "Verify PZEM-004T serial UART connection and power supply.",
        "normal_range": "Valid reading (non-null)",
        "measured_val_func": lambda tel: f"Voltage: {tel.get('pzem_voltage')}V, Current: {tel.get('pzem_current')}A",
        "unit": ""
    },
    {
        "id": "temp1_offline",
        "label": "Outlet Temp Probe Offline",
        "description": "Checks if DS18B20 outlet temperature probe is missing/null",
        "check": lambda tel: tel.get("ds18b20_temp1") is None,
        "issue": "Outlet Temp Probe Offline",
        "severity": "High",
        "root_cause": "The DS18B20 outlet compressor temperature probe returned no data.",
        "recommended_action": "Check DS18B20 outlet temperature probe wire connection to GPIO Pin 33.",
        "normal_range": "Valid reading (non-null)",
        "measured_val_func": lambda tel: f"Outlet: {tel.get('ds18b20_temp1')}°C",
        "unit": ""
    },
    {
        "id": "temp2_offline",
        "label": "Inlet Temp Probe Offline",
        "description": "Checks if DS18B20 inlet temperature probe is missing/null",
        "check": lambda tel: tel.get("ds18b20_temp2") is None,
        "issue": "Inlet Temp Probe Offline",
        "severity": "High",
        "root_cause": "The DS18B20 inlet compressor temperature probe returned no data.",
        "recommended_action": "Check DS18B20 inlet temperature probe wire connection to GPIO Pin 25.",
        "normal_range": "Valid reading (non-null)",
        "measured_val_func": lambda tel: f"Inlet: {tel.get('ds18b20_temp2')}°C",
        "unit": ""
    },
    {
        "id": "dust_offline",
        "label": "Dust Sensor Offline",
        "description": "Checks if dust sensor reading is missing/null",
        "check": lambda tel: tel.get("dust_sensor") is None,
        "issue": "Dust Sensor Offline",
        "severity": "Low",
        "root_cause": "The GP2Y1010 dust sensor returned no reading.",
        "recommended_action": "Verify dust sensor wiring connection.",
        "normal_range": "Valid reading (non-null)",
        "measured_val_func": lambda tel: f"Dust: {tel.get('dust_sensor')} µg/m³",
        "unit": ""
    },
    {
        "id": "vibration_offline",
        "label": "Vibration Sensor Offline",
        "description": "Checks if vibration sensor reading is missing/null",
        "check": lambda tel: tel.get("vibration") is None,
        "issue": "Vibration Sensor Offline",
        "severity": "Medium",
        "root_cause": "The ADXL345 vibration sensor I2C communication is offline.",
        "recommended_action": "Check ADXL345 I2C connections (SDA/SCL) and verify pull-up resistors.",
        "normal_range": "Valid reading (non-null)",
        "measured_val_func": lambda tel: f"Vib: {tel.get('vibration')} Hz",
        "unit": ""
    },

    # ── COMBINED ALERTS (1 to 4) ──────────────────────────────
    {
        "id": "compressor_overheating",
        "label": "Compressor Overheating",
        "description": "Deterministic safety check: Current >= 8.8 A AND Power >= 1860 W AND Vibration >= 90 Hz",
        "check": is_overheating,
        "issue": "Compressor Overheating",
        "severity": "High",
        "root_cause": "Indicates the compressor is under high electrical and mechanical load, commonly associated with reduced condenser cooling efficiency or compressor overloading.",
        "recommended_action": "Check whether the condenser fan is operating properly. Stop operating the air conditioner if the current continues to increase to prevent compressor damage and protect the electrical wiring and circuit breaker.",
        "normal_range": "Current < 8.8 A OR Power < 1860 W OR Vibration < 90 Hz",
        "measured_val_func": lambda tel: f"Current: {tel.get('pzem_current')} A, Power: {tel.get('pzem_power')} W, Vibration: {tel.get('vibration')} Hz",
        "unit": ""
    },
    {
        "id": "reduced_cooling",
        "label": "Reduced Cooling Performance",
        "description": "Deterministic check: Outlet Compressor >= 61°C AND Output Air >= 21°C AND Inlet >= 22°C",
        "check": is_reduced_cooling,
        "issue": "Reduced Cooling Performance",
        "severity": "Medium",
        "root_cause": "The monitored temperatures indicate a reduction in cooling performance. Inspect the refrigerant system for possible refrigerant leakage or insufficient refrigerant charge.",
        "recommended_action": "The monitored temperatures indicate a reduction in cooling performance. Inspect the refrigerant system for possible refrigerant leakage or insufficient refrigerant charge. Verify the condition using appropriate refrigeration service equipment and perform corrective maintenance if necessary.",
        "normal_range": "Outlet < 61°C OR Output < 21°C OR Inlet < 22°C",
        "measured_val_func": lambda tel: f"Outlet: {tel.get('ds18b20_temp1')}°C, Output: {tel.get('dht_temp')}°C, Inlet: {tel.get('ds18b20_temp2')}°C",
        "unit": "°C"
    },

    # ── INDIVIDUAL ALERTS ─────────────────────────────────────
    {
        "id": "high_voltage",
        "label": "High Voltage Supply",
        "description": "Voltage supply check (> 241 V)",
        "check": lambda tel: tel.get("pzem_voltage") is not None and float(tel.get("pzem_voltage")) > 241.0,
        "issue": "High Voltage - Overvoltage supply",
        "severity": "High",
        "root_cause": "Voltage supply exceeds the safe operating limit of 241 V.",
        "recommended_action": "Verify input voltage stability and check voltage regulator status.",
        "normal_range": "≤ 241 V",
        "measured_val_func": lambda tel: f"{tel.get('pzem_voltage')} V",
        "unit": "V"
    },
    {
        "id": "low_voltage",
        "label": "Low Voltage Supply",
        "description": "Voltage supply check (< 225 V)",
        "check": lambda tel: tel.get("pzem_voltage") is not None and float(tel.get("pzem_voltage")) < 225.0,
        "issue": "Low Voltage - Undervoltage supply",
        "severity": "High",
        "root_cause": "Voltage supply is below the safe operating limit of 225 V.",
        "recommended_action": "Verify input voltage stability and check voltage regulator status.",
        "normal_range": "≥ 225 V",
        "measured_val_func": lambda tel: f"{tel.get('pzem_voltage')} V",
        "unit": "V"
    },
    {
        "id": "high_inlet_temp",
        "label": "High Inlet Temperature",
        "description": "Inlet compressor suction temp check (> 17 °C)",
        "check": lambda tel: tel.get("ds18b20_temp2") is not None and float(tel.get("ds18b20_temp2")) > 17.0 and not is_reduced_cooling(tel),
        "issue": "High Inlet Temperature (Suction) — Dirty evaporator coil",
        "severity": "High",
        "root_cause": "Inlet compressor suction line temperature is above the safe operating limit of 17 °C.",
        "recommended_action": "Inspect suction line insulation, check expansion valve operation, and verify refrigerant charge.",
        "normal_range": "≤ 17.0 °C",
        "measured_val_func": lambda tel: f"{tel.get('ds18b20_temp2')} °C",
        "unit": "°C"
    },
    {
        "id": "low_inlet_temp",
        "label": "Low Inlet Temperature",
        "description": "Inlet compressor suction temp check (< 8 °C)",
        "check": lambda tel: tel.get("ds18b20_temp2") is not None and float(tel.get("ds18b20_temp2")) < 8.0 and not is_reduced_cooling(tel),
        "issue": "Low Inlet Temperature (Suction) — faulty thermostat",
        "severity": "High",
        "root_cause": "Inlet compressor suction line temperature is below the safe operating limit of 8 °C.",
        "recommended_action": "Inspect suction line insulation, check expansion valve operation, and verify refrigerant charge.",
        "normal_range": "≥ 8.0 °C",
        "measured_val_func": lambda tel: f"{tel.get('ds18b20_temp2')} °C",
        "unit": "°C"
    },
    {
        "id": "high_outlet_temp",
        "label": "High Outlet Compressor Temp",
        "description": "Outlet compressor discharge temp check (> 61 °C)",
        "check": lambda tel: tel.get("ds18b20_temp1") is not None and float(tel.get("ds18b20_temp1")) > 61.0 and not is_reduced_cooling(tel),
        "issue": "High Outlet Temperature (Discharge) — Dirty condenser coil",
        "severity": "High",
        "root_cause": "Outlet compressor discharge line temperature is above the safe operating limit of 61 °C.",
        "recommended_action": "Check whether the condenser fan is operating properly. Stop operating the air conditioner if the current continues to increase to prevent compressor damage and protect the electrical wiring and circuit breaker.",
        "normal_range": "≤ 61.0 °C",
        "measured_val_func": lambda tel: f"{tel.get('ds18b20_temp1')} °C",
        "unit": "°C"
    },
    {
        "id": "low_outlet_temp",
        "label": "Low Outlet Compressor Temp",
        "description": "Outlet compressor discharge temp check (< 50 °C)",
        "check": lambda tel: tel.get("ds18b20_temp1") is not None and float(tel.get("ds18b20_temp1")) < 50.0 and not is_reduced_cooling(tel),
        "issue": "Low Outlet Temperature (Discharge) — Low refrigerant charge",
        "severity": "High",
        "root_cause": "Outlet compressor discharge line temperature is below the safe operating limit of 50 °C.",
        "recommended_action": "Check compressor operation and verify system refrigerant level.",
        "normal_range": "≥ 50.0 °C",
        "measured_val_func": lambda tel: f"{tel.get('ds18b20_temp1')} °C",
        "unit": "°C"
    },
    {
        "id": "low_vibration",
        "label": "Low Vibration",
        "description": "Compressor low vibration check (< 10 Hz)",
        "check": lambda tel: tel.get("vibration") is not None and float(tel.get("vibration")) < 10.0,
        "issue": "Low Vibration — Compressor not operating, fan not running or off",
        "severity": "High",
        "root_cause": "Vibration frequency is abnormally low, suggesting the unit is not running or operating.",
        "recommended_action": "Verify power supply to compressor and fan; check starter capacitors and contactors.",
        "normal_range": "≥ 10 Hz",
        "measured_val_func": lambda tel: f"{tel.get('vibration')} Hz",
        "unit": "Hz"
    },
    {
        "id": "excessive_vibration",
        "label": "Excessive Vibration",
        "description": "Compressor excessive vibration check (>= 90 Hz)",
        "check": lambda tel: tel.get("vibration") is not None and float(tel.get("vibration")) >= 90.0 and not is_overheating(tel),
        "issue": "Excessive Vibration — Loose compressor mounting, worn bearings, condenser fan imbalance",
        "severity": "Medium",
        "root_cause": "Vibration frequency exceeds the safety threshold of 90 Hz.",
        "recommended_action": "Inspect the compressor mounting, internal components, and check for signs of compressor wear or mechanical looseness.",
        "normal_range": "< 90 Hz",
        "measured_val_func": lambda tel: f"{tel.get('vibration')} Hz",
        "unit": "Hz"
    },
    {
        "id": "low_dust",
        "label": "Low Dust Concentration",
        "description": "Dust sensor consistently zero check (== 0 µg/m³)",
        "check": lambda tel: tel.get("dust_sensor") is not None and float(tel.get("dust_sensor")) <= 0.001,
        "issue": "Low Dust Sensor — Clean air path, recently cleaned filter, or possible dust sensor malfunction if consistently zero",
        "severity": "Low",
        "root_cause": "Dust concentration reading is exactly zero, which may indicate a recently cleaned filter or a sensor malfunction.",
        "recommended_action": "Check dust sensor calibration and verify clean air path.",
        "normal_range": "> 0 µg/m³",
        "measured_val_func": lambda tel: f"{tel.get('dust_sensor')} µg/m³",
        "unit": "µg/m³"
    },
    {
        "id": "excessive_dust",
        "label": "Excessive Dust Sensor",
        "description": "Dust sensor threshold check (>= 340 µg/m³)",
        "check": lambda tel: tel.get("dust_sensor") is not None and float(tel.get("dust_sensor")) >= 340.0,
        "issue": "Excessive Dust Sensor — Dirty air filter",
        "severity": "Low",
        "root_cause": "Dust concentration exceeds the safe threshold of 340 µg/m³.",
        "recommended_action": "Clean the air filter and inspect the evaporator section for dust accumulation that may restrict airflow.",
        "normal_range": "< 340 µg/m³",
        "measured_val_func": lambda tel: f"{tel.get('dust_sensor')} µg/m³",
        "unit": "µg/m³"
    },
    {
        "id": "individual_current_low",
        "label": "Low Current Draw",
        "description": "Current draw check (< 7.6 A)",
        "check": lambda tel: tel.get("pzem_current") is not None and float(tel.get("pzem_current")) < 7.6,
        "issue": "Low Current Anomaly",
        "severity": "High",
        "root_cause": "Current draw is below the normal operating limit of 7.6 A.",
        "recommended_action": "Inspect electrical wiring and check compressor loading.",
        "normal_range": "≥ 7.6 A",
        "measured_val_func": lambda tel: f"{tel.get('pzem_current')} A",
        "unit": "A"
    },
    {
        "id": "individual_current_high",
        "label": "High Current Draw",
        "description": "Current draw check (> 8.8 A)",
        "check": lambda tel: tel.get("pzem_current") is not None and float(tel.get("pzem_current")) > 8.8 and not is_overheating(tel),
        "issue": "High Current Anomaly",
        "severity": "High",
        "root_cause": "Current draw is above the normal operating limit of 8.8 A.",
        "recommended_action": "Inspect electrical wiring, connections, and check compressor motor draws.",
        "normal_range": "≤ 8.8 A",
        "measured_val_func": lambda tel: f"{tel.get('pzem_current')} A",
        "unit": "A"
    },
    {
        "id": "individual_power_low",
        "label": "Low Power Consumption",
        "description": "Power draw check (< 1650 W)",
        "check": lambda tel: tel.get("pzem_power") is not None and float(tel.get("pzem_power")) < 1650.0,
        "issue": "Low Power Anomaly",
        "severity": "High",
        "root_cause": "Power draw is below the normal operating limit of 1650 W.",
        "recommended_action": "Check line voltage stability and compressor capacitors.",
        "normal_range": "≥ 1650 W",
        "measured_val_func": lambda tel: f"{tel.get('pzem_power')} W",
        "unit": "W"
    },
    {
        "id": "individual_power_high",
        "label": "High Power Consumption",
        "description": "Power draw check (> 1860 W)",
        "check": lambda tel: tel.get("pzem_power") is not None and float(tel.get("pzem_power")) > 1860.0 and not is_overheating(tel),
        "issue": "High Power Anomaly",
        "severity": "High",
        "root_cause": "Power draw is above the normal operating limit of 1860 W.",
        "recommended_action": "Check compressor electrical loading and verify line stability.",
        "normal_range": "≤ 1860 W",
        "measured_val_func": lambda tel: f"{tel.get('pzem_power')} W",
        "unit": "W"
    },
    {
        "id": "individual_output_temp_low",
        "label": "Low Output Temp",
        "description": "Supply air output temp check (< 7 °C)",
        "check": lambda tel: tel.get("dht_temp") is not None and float(tel.get("dht_temp")) < 7.0 and not is_reduced_cooling(tel),
        "issue": "Low Output Temp Anomaly",
        "severity": "High",
        "root_cause": "Supply air output temperature is below the safe limit of 7 °C.",
        "recommended_action": "Inspect evaporator for frost buildup, verify fan operation.",
        "normal_range": "≥ 7.0 °C",
        "measured_val_func": lambda tel: f"{tel.get('dht_temp')} °C",
        "unit": "°C"
    },
    {
        "id": "individual_output_temp_high",
        "label": "High Output Temp",
        "description": "Supply air output temp check (> 25 °C)",
        "check": lambda tel: tel.get("dht_temp") is not None and float(tel.get("dht_temp")) > 25.0 and not is_reduced_cooling(tel),
        "issue": "High Output Temp Anomaly",
        "severity": "High",
        "root_cause": "Supply air output temperature is above the safe limit of 25 °C.",
        "recommended_action": "Inspect evaporator fan, clean filter, and check for correct air discharge.",
        "normal_range": "≤ 25.0 °C",
        "measured_val_func": lambda tel: f"{tel.get('dht_temp')} °C",
        "unit": "°C"
    },
    {
        "id": "dht_humidity",
        "label": "Humidity",
        "description": "Relative humidity check (<= 80%)",
        "check": lambda tel: tel.get("dht_humidity") is not None and float(tel.get("dht_humidity")) > 80.0,
        "issue": "Humidity Anomaly",
        "severity": "Low",
        "root_cause": "Relative humidity exceeds the normal operating limit of 80%.",
        "recommended_action": "Verify indoor fan speeds, check return air humidity, and confirm condensate drainage.",
        "normal_range": "≤ 80 %",
        "measured_val_func": lambda tel: f"{tel.get('dht_humidity')} %",
        "unit": "%"
    }
]

def analyze_with_rules(telemetry: dict) -> dict:
    findings = []
    computation_steps = []
    severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    overall_severity = None
    sensors_checked = 0
    sensors_triggered = 0

    for rule in RULES:
        sensors_checked += 1
        triggered = False
        try:
            triggered = rule["check"](telemetry)
        except Exception:
            pass

        measured_val = rule["measured_val_func"](telemetry)

        if triggered:
            finding = {
                "sensor":              rule["label"],
                "sensor_key":          rule["id"],
                "measured_value":      measured_val,
                "unit":                rule["unit"],
                "normal_range":        rule["normal_range"],
                "computed_expression": f"Triggered: {measured_val}",
                "issue":               rule["issue"],
                "severity":            rule["severity"],
                "status":              "Current",
                "root_cause":          rule["root_cause"],
                "recommended_action":  rule["recommended_action"],
            }
            findings.append(finding)

            rank = severity_rank.get(rule["severity"], 0)
            if overall_severity is None or rank > severity_rank.get(overall_severity, 0):
                overall_severity = rule["severity"]

            computation_steps.append({
                "sensor":       rule["label"],
                "value":        measured_val,
                "normal_range": rule["normal_range"],
                "result":       "TRIGGERED",
                "expression":   f"Value {measured_val} triggers threshold",
                "severity":     rule["severity"],
                "issue":        rule["issue"],
            })
            sensors_triggered += 1
        else:
            computation_steps.append({
                "sensor":       rule["label"],
                "value":        measured_val,
                "normal_range": rule["normal_range"],
                "result":       "PASS",
                "reason":       "Value within normal operating range",
            })

    return {
        "findings":          findings,
        "overall_severity":  overall_severity or "Normal",
        "sensors_checked":   sensors_checked,
        "sensors_triggered": sensors_triggered,
        "computation_steps": computation_steps,
    }
