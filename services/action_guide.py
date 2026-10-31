"""
"What do I do now?" guide for AirBnBrrr alerts.

Turns the rule-engine findings (and what the per-AC model found odd) into a short, ordered
action plan: how urgent it is, what to do right now, what to check, and when to call a technician.
The plan is saved inside the alert (diagnoses -> action_plan), shown on the alert page, and the top
steps are put in the ntfy notification.

Advice is general guidance for a window-type, non-inverter AC. It is not a replacement for a
qualified technician, especially for electrical and refrigerant work.
"""

URGENCY_ORDER = {"stop_now": 0, "today": 1, "soon": 2, "sensor": 3, "clean": 4}
URGENCY_LABEL = {
    "stop_now": "Stop and check now",
    "today": "Check today",
    "soon": "Plan maintenance",
    "sensor": "Check the sensor",
    "clean": "Routine cleaning",
}
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

# Names a person understands instead of column names.
FRIENDLY = {
    "pzem_current": "current", "pzem_voltage": "voltage", "pzem_power": "power",
    "pzem_power_factor": "power factor", "pzem_frequency": "line frequency",
    "dht_temp": "output air temperature", "dht_humidity": "output humidity",
    "ds18b20_temp1": "outlet compressor temperature", "ds18b20_temp2": "inlet compressor temperature",
    "vibration": "compressor vibration", "dust_sensor": "dust level",
}

RESTART = "Wait at least 5 minutes before turning it back on, then restart once and watch the readings."

_CURRENT = dict(
    urgency="stop_now",
    do_now=[
        "Switch the AC off at the remote and unplug it or switch off its breaker if the current stays above 8.8 A. Do not keep it running.",
        RESTART,
    ],
    check=[
        "Outdoor side (condenser): dirty coil, blocked airflow, fan not spinning.",
        "Plug, socket and wire: if the plug or socket is warm or discolored, stop using it.",
        "Check the voltage alert too: low voltage makes the compressor draw more current.",
    ],
    call="the current is above 8.8 A again after cleaning and a restart, the breaker trips, or you smell burning.",
)
_VOLTAGE = dict(
    urgency="today",
    do_now=[
        "If the voltage stays outside 225-241 V for more than a few minutes, switch the AC off. A bad supply can damage the compressor.",
        RESTART,
    ],
    check=[
        "Other heavy appliances on the same line, and loose main or neutral connections.",
        "Whether a voltage regulator (AVR) or protector is installed and working.",
        "Ask your electric utility or an electrician if the supply is unstable.",
    ],
    call="the voltage keeps leaving the 225-241 V range, even with other appliances off.",
)
_NOT_RUNNING = dict(
    urgency="today",
    do_now=[
        "Check that the AC is switched on, set to a cooling mode, and the thermostat is set below the room temperature. If you turned it off yourself, you can ignore this.",
        "Listen for the compressor starting. If only the fan runs, the compressor is not starting.",
    ],
    check=[
        "Power supply to the compressor and fan.",
        "Starting capacitor and contactor (a technician job).",
    ],
    call="the fan runs but the compressor never starts, or the unit trips the breaker.",
)
_DIRTY_COIL = dict(
    urgency="today",
    do_now=[
        "Turn the AC off and let it rest, then clean the air filter and check that nothing blocks the air flow.",
        "Restart and watch whether the temperature comes back into range within 15 minutes.",
    ],
    check=[
        "Dirty evaporator (indoor) coil and filter.",
        "Suction line insulation and the refrigerant charge.",
    ],
    call="the temperature is still out of range after cleaning.",
)
_OUTLET_HIGH = dict(
    urgency="stop_now",
    do_now=[
        "Check that the outdoor condenser fan is spinning and the coil is not blocked. Switch the AC off if the current is also rising.",
        RESTART,
    ],
    check=["Dirty condenser coil.", "Condenser fan motor or capacitor.", "Hot air from the outlet being pulled back in (blocked or too close to a wall)."],
    call="the outlet temperature goes above 61 C again after cleaning, which can damage the compressor.",
)
_REFRIGERANT = dict(
    urgency="today",
    do_now=[
        "Keep the AC off if it is not cooling, and avoid repeated restarts.",
        "Look for oil stains or frost on the pipes, and compare the cooling with the previous days.",
    ],
    check=["Refrigerant charge and possible leak.", "Compressor operation."],
    call="cooling stays weak. Refrigerant work must be done by a technician.",
)

GUIDE = {
    "individual_current_high": dict(_CURRENT, title="Current is too high"),
    "compressor_overheating": dict(_CURRENT, title="Compressor is overloaded and overheating"),
    "individual_power_high": dict(_CURRENT, title="Power draw is too high"),
    "high_voltage": dict(_VOLTAGE, title="Supply voltage is too high"),
    "low_voltage": dict(_VOLTAGE, title="Supply voltage is too low"),
    "individual_current_low": dict(_NOT_RUNNING, title="Current is lower than normal"),
    "individual_power_low": dict(_NOT_RUNNING, title="Power draw is lower than normal"),
    "low_vibration": dict(_NOT_RUNNING, title="Compressor does not seem to be running"),
    "high_inlet_temp": dict(_DIRTY_COIL, title="Inlet compressor temperature is too high"),
    "individual_output_temp_high": dict(_DIRTY_COIL, title="Output air is too warm"),
    "high_outlet_temp": dict(_OUTLET_HIGH, title="Outlet compressor temperature is too high"),
    "reduced_cooling": dict(_REFRIGERANT, title="Cooling performance has dropped"),
    "low_outlet_temp": dict(_REFRIGERANT, title="Outlet compressor temperature is too low"),
    "low_inlet_temp": dict(
        urgency="today",
        do_now=["Turn the AC off for 30 minutes to let any ice melt.", "Restart with a higher thermostat setting and clean the filter."],
        check=["Frost on the indoor coil or pipes.", "Thermostat sensor and airflow."],
        call="it freezes up again.", title="Inlet temperature is too low (possible freezing)"),
    "individual_output_temp_low": dict(
        urgency="today",
        do_now=["Turn the AC off to let any frost melt, clean the filter, then restart."],
        check=["Frost buildup on the evaporator.", "Indoor fan speed and airflow."],
        call="the output air is still very cold after cleaning.", title="Output air is too cold"),
    "excessive_vibration": dict(
        urgency="today",
        do_now=["Listen for rattling or grinding. Switch the AC off if it is loud or getting worse."],
        check=["Compressor mounting bolts and rubber feet.", "Condenser fan blade balance.", "Worn compressor bearings."],
        call="the vibration continues after tightening the mounting, or you hear grinding.",
        title="Compressor vibration is too high"),
    "excessive_dust": dict(
        urgency="clean",
        do_now=["Remove and clean the air filter, then dry it fully before putting it back."],
        check=["Dust on the evaporator coil.", "Whether the dust sensor itself is dirty."],
        call="the dust reading stays high after cleaning.", title="Too much dust, filter needs cleaning"),
    "low_dust": dict(
        urgency="sensor",
        do_now=["If the filter was just cleaned this is fine. If the reading is exactly zero all the time, check the dust sensor."],
        check=["Dust sensor wiring and calibration."],
        call="it is always zero.", title="Dust sensor reads zero"),
    "dht_humidity": dict(
        urgency="soon",
        do_now=["Check that the condensate drain is not blocked and the indoor fan is running."],
        check=["Return air humidity.", "Water dripping or pooling at the unit."],
        call="humidity stays above 80% for days.", title="Humidity is too high"),
    "dht_offline": dict(urgency="sensor", do_now=["Check the DHT22 sensor wiring and power."], check=["GPIO pin 18, VCC and GND."], call="the sensor stays offline after re-seating the wires.", title="Temperature and humidity sensor offline"),
    "pzem_offline": dict(urgency="sensor", do_now=["Check the PZEM power meter wiring and power. Switch the AC off at the breaker before touching any mains wiring."], check=["Serial (UART) connection to the ESP32."], call="the meter stays offline. Mains wiring needs a qualified person.", title="Power meter offline"),
    "temp1_offline": dict(urgency="sensor", do_now=["Check the outlet temperature probe wire."], check=["DS18B20 probe on GPIO pin 33."], call="the probe stays offline.", title="Outlet temperature probe offline"),
    "temp2_offline": dict(urgency="sensor", do_now=["Check the inlet temperature probe wire."], check=["DS18B20 probe on GPIO pin 25."], call="the probe stays offline.", title="Inlet temperature probe offline"),
    "dust_offline": dict(urgency="sensor", do_now=["Check the dust sensor wiring."], check=["GP2Y1010 sensor connection."], call="the sensor stays offline.", title="Dust sensor offline"),
    "vibration_offline": dict(urgency="sensor", do_now=["Check the vibration sensor connections."], check=["ADXL345 I2C wires (SDA/SCL)."], call="the sensor stays offline.", title="Vibration sensor offline"),
}

# What to look at when only the AI model flagged something (no rule fired).
FEATURE_HINTS = {
    "pzem_current": "Check the condenser coil and fan, the plug and socket, and the supply voltage.",
    "pzem_power": "Check the condenser coil and fan, and compare with the current and voltage.",
    "pzem_voltage": "Check the supply: other heavy loads on the same line, loose connections, voltage regulator.",
    "pzem_power_factor": "Power factor drifting often means a weak or failing capacitor or motor. Compare with the current reading.",
    "pzem_frequency": "Line frequency should be steady. Large changes point to the power supply or a generator.",
    "dht_temp": "Check the filter and indoor airflow.",
    "dht_humidity": "Check the condensate drain and indoor fan.",
    "ds18b20_temp1": "Check the condenser coil and fan (outlet compressor line).",
    "ds18b20_temp2": "Check the evaporator coil, filter and refrigerant charge (inlet compressor line).",
    "vibration": "Listen for rattling and check the compressor mounting.",
    "dust_sensor": "Check and clean the air filter.",
}


def short_name(issue):
    return (issue or "").split(" \u2014 ")[0].split(" - ")[0].strip()


def fmt_measured(f):
    """Measured value with its unit once (the rule engine often already includes the unit)."""
    val = str(f.get("measured_value", "")).strip()
    unit = (f.get("unit") or "").strip()
    if val and unit and unit not in val:
        val = f"{val} {unit}"
    return val


def ml_features(ml):
    return [(n, z) for n, z in ((ml or {}).get("top_features") or [])]


def ml_line(ml):
    odd = ml_features(ml)
    if not odd:
        return "AI model: this AC is behaving differently from its own normal" if ml and ml.get("is_anomaly") else None
    parts = ", ".join(f"{FRIENDLY.get(n, n)} ({z:g}x normal variation)" for n, z in odd)
    return f"AI model: this AC is behaving unusually: {parts}"


def _step_for(f):
    g = GUIDE.get(f.get("sensor_key"))
    urgency = g["urgency"] if g else ("stop_now" if f.get("severity") in ("High", "Critical") else "soon")
    do_now = list(g["do_now"]) if g else [f.get("recommended_action") or "Inspect the unit."]
    check = list(g["check"]) if g else []
    if g and f.get("recommended_action"):
        check.append(f["recommended_action"])      # keep the rule engine's own advice too
    return {
        "id": f.get("sensor_key"),
        "title": (g or {}).get("title") or short_name(f.get("issue")),
        "severity": f.get("severity"),
        "urgency": urgency,
        "measured": fmt_measured(f),
        "normal": f.get("normal_range"),
        "why": f.get("root_cause"),
        "do_now": do_now,
        "check": check,
        "call_technician_if": (g or {}).get("call"),
    }


def _sort_key(s):
    return (URGENCY_ORDER.get(s["urgency"], 9), -SEVERITY_RANK.get(s["severity"], 0))


def build_plan(findings, ml=None):
    """Ordered action plan: headline, the first things to do, and a detailed step per problem."""
    steps, seen = [], set()
    for f in findings or []:
        if f.get("sensor_key") in seen:
            continue
        seen.add(f.get("sensor_key"))
        steps.append(_step_for(f))
    steps.sort(key=_sort_key)

    odd = ml_features(ml)
    ml_notes = [{"sensor": FRIENDLY.get(n, n), "times_normal": z, "hint": FEATURE_HINTS.get(n, "")} for n, z in odd]
    if not steps and ml and ml.get("is_anomaly"):
        # only the AI model noticed something: build the steps from what looked odd
        steps.append({
            "id": "ai_model", "title": "This AC is behaving differently from its own normal", "severity": "Medium",
            "urgency": "today", "measured": "", "normal": "", "why": "No fixed limit was broken, but the readings no longer look like this AC's usual pattern.",
            "do_now": ["Look at the AC: listen for new noises, feel the air temperature, check the filter."] + [m["hint"] for m in ml_notes if m["hint"]][:2],
            "check": ["Compare the readings with a normal day on the graphs."],
            "call_technician_if": "it keeps happening for more than a day or the cooling gets worse.",
        })

    top = steps[0]["urgency"] if steps else "today"
    first_steps = []
    for s in steps:
        line = f"{s['title']}: {s['do_now'][0]}"
        if line not in first_steps:
            first_steps.append(line)
    return {
        "urgency": top,
        "headline": URGENCY_LABEL.get(top, "Check the AC"),
        "first_steps": first_steps[:3],
        "steps": steps,
        "ml_notes": ml_notes,
    }


def short_actions(findings, ml=None, n=3):
    """The few most important things to do, one line each (used in the ntfy notification)."""
    return build_plan(findings, ml)["first_steps"][:n]
