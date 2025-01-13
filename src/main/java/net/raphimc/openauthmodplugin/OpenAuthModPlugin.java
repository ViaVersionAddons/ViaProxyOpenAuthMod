/*
 * This file is part of ViaProxyOpenAuthMod - https://github.com/ViaVersionAddons/ViaProxyOpenAuthMod
 * Copyright (C) 2024-2025 RK_01/RaphiMC and contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.raphimc.openauthmodplugin;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import net.lenni0451.lambdaevents.EventHandler;
import net.lenni0451.reflect.Enums;
import net.lenni0451.reflect.stream.RStream;
import net.raphimc.netminecraft.packet.PacketTypes;
import net.raphimc.viaproxy.ViaProxy;
import net.raphimc.viaproxy.plugins.ViaProxyPlugin;
import net.raphimc.viaproxy.plugins.events.ConnectEvent;
import net.raphimc.viaproxy.plugins.events.JoinServerRequestEvent;
import net.raphimc.viaproxy.plugins.events.ViaProxyLoadedEvent;
import net.raphimc.viaproxy.protocoltranslator.viaproxy.ViaProxyConfig;
import net.raphimc.viaproxy.ui.I18n;

import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class OpenAuthModPlugin extends ViaProxyPlugin {

    private static ViaProxyConfig.AuthMethod OPENAUTHMOD;

    @Override
    public void onEnable() {
        ViaProxy.EVENT_MANAGER.register(this);

        OPENAUTHMOD = Enums.newInstance(ViaProxyConfig.AuthMethod.class, "OPENAUTHMOD", ViaProxyConfig.AuthMethod.values().length, new Class[]{String.class}, new Object[]{"openauthmod.auth_method.name"});
        Enums.addEnumInstance(ViaProxyConfig.AuthMethod.class, OPENAUTHMOD);
    }

    @EventHandler
    private void onViaProxyLoaded(ViaProxyLoadedEvent event) {
        final Map<String, Properties> locales = RStream.of(I18n.class).fields().by("LOCALES").get();
        locales.get("en_US").setProperty(OPENAUTHMOD.getGuiTranslationKey(), "Use OpenAuthMod");
    }

    @EventHandler
    private void onConnect(ConnectEvent event) {
        event.getProxyConnection().getPacketHandlers().add(0, new OpenAuthModPacketHandler(event.getProxyConnection()));
    }

    @EventHandler
    private void onJoinServerRequest(JoinServerRequestEvent event) throws ExecutionException, InterruptedException {
        if (ViaProxy.getConfig().getAuthMethod() == OPENAUTHMOD) {
            try {
                final ByteBuf response = event.getProxyConnection().getPacketHandler(OpenAuthModPacketHandler.class).sendCustomPayload(OpenAuthModConstants.JOIN_CHANNEL, PacketTypes.writeString(Unpooled.buffer(), event.getServerIdHash())).get(6, TimeUnit.SECONDS);
                if (response == null) throw new TimeoutException();
                if (response.isReadable() && !response.readBoolean()) throw new TimeoutException();
                event.setCancelled(true);
            } catch (TimeoutException e) {
                event.getProxyConnection().kickClient("§cAuthentication cancelled! You need to install the OpenAuthMod client mod in order to join this server.");
            }
        }
    }

}
