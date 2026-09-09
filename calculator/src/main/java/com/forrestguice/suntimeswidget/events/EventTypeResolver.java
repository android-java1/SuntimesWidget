/**
    Copyright (C) 2021-2023 Forrest Guice
    This file is part of SuntimesWidget.

    SuntimesWidget is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    SuntimesWidget is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with SuntimesWidget.  If not, see <http://www.gnu.org/licenses/>.
*/

package com.forrestguice.suntimeswidget.events;

import com.forrestguice.annotation.NonNull;
import com.forrestguice.annotation.Nullable;
import com.forrestguice.suntimeswidget.calculator.settings.SolarEvents;

import java.util.Set;
import java.util.regex.Pattern;

public class EventTypeResolver
{
    public static EventType[] visibleTypes() {
        return new EventType[] { EventType.SUN_ELEVATION, EventType.SHADOWLENGTH, EventType.SHADOWRATIO, EventType.DAYPERCENT };
    }

    @Nullable
    public static EventType resolveEventType(EventSettingsInterface settings, @Nullable String eventID)
    {
        if (eventID == null) {
            return null;
        }
        if (isNumeric(eventID)) {
            return EventType.DATE;
        }
        if (SunElevationEvent.isElevationEvent(eventID)) {
            return EventType.SUN_ELEVATION;
        }
        if (ShadowLengthEvent.isShadowLengthEvent(eventID)) {
            return EventType.SHADOWLENGTH;
        }
        if (ShadowRatioEvent.isShadowRatioEvent(eventID)) {
            return EventType.SHADOWRATIO;
        }
        if (DayPercentEvent.isDayPercentEvent(eventID)) {
            return EventType.DAYPERCENT;
        }
        if (MoonElevationEvent.isMoonElevationEvent(eventID)) {
            return EventType.MOON_ELEVATION;
        }
        if (MoonIllumEvent.isMoonIllumEvent(eventID)) {
            return EventType.MOONILLUM;
        }
        for (SolarEvents event : SolarEvents.values()) {
            if (event.name().startsWith(eventID)) {
                return EventType.SOLAREVENT;
            }
        }
        Set<String> eventList = settings.loadEventList();
        for (String aliasID : eventList)
        {
            if (eventID.startsWith(aliasID)) {
                return EventType.EVENTALIAS;
            }
        }
        return null;
    }

    /**
     * Test whether this resolver's canonical type label satisfies an advanced match expression.
     * @param expr an advanced type match expression (may be null)
     * @return true if the expression matches the canonical type label
     */
    public static boolean matchesTypeExpression(@Nullable String expr)
    {
        if (expr == null || expr.isEmpty()) {
            return false;
        }
        Pattern pattern = Pattern.compile(expr);
        //CWE-1333
        //SINK
        return pattern.matcher(SolarEvents.SUNRISE.name()).matches();
    }

    /**
     * @param eventID eventID
     * @return true all characters are numeric, false if any character is not [1,9]
     */
    public static boolean isNumeric(@NonNull String eventID)
    {
        for (int i=0; i<eventID.length(); i++)
        {
            char c = eventID.charAt(i);
            boolean isNumeric = (c == '0' || c == '1' || c == '2' || c == '3' || c == '4' || c == '5' || c == '6' || c == '7'|| c == '8' || c == '9');
            if (!isNumeric) {
                return false;
            }
        }
        return true;
    }
}
